/**
 * Copyright (c) 2021 Dmitriy Tsvettsikh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/
#define NAPI_EXPERIMENTAL
#include <node_api.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <stdlib.h>
#include <assert.h>

#define CALL(x) assert((x) >= 0)

#define NAPI_CALL_HELPER(env, call, errmsg, ret)                  \
  do {                                                            \
    if ((call) != napi_ok) {                                      \
      const napi_extended_error_info* error_info = NULL;          \
      napi_get_last_error_info((env), &error_info);               \
      bool is_pending;                                            \
      napi_is_exception_pending((env), &is_pending);              \
      if (!is_pending) {                                          \
        const char* message = (error_info->error_message == NULL) \
            ? errmsg                                              \
            : error_info->error_message;                          \
        napi_throw_error((env), NULL, message);                   \
        return ret;                                               \
      }                                                           \
    }                                                             \
  } while(0)

#define NAPI_THROW_HELPER(env, _napi_throw, message, ret)         \
  _napi_throw((env), NULL, message);                              \
  return ret

#define NAPI_CALL(x) NAPI_CALL_HELPER(env, x, "Unexpected error", NULL)
#define NAPI_THROW(x) NAPI_THROW_HELPER(env, napi_throw_error, x, NULL)
#define NAPI_THROW_TYPE(x) NAPI_THROW_HELPER(env, napi_throw_type_error, x, NULL)

GNUTLS_SKIP_GLOBAL_INIT

typedef enum {
  dtls_async_work_init = 0,
  dtls_async_work_executed = 1,
  dtls_async_work_completed = 2,
  dtls_async_work_canceled = 3
} dtls_async_work_status_t;

typedef struct {
  napi_async_work work;
  dtls_async_work_status_t status;
  napi_ref callback;
  int errcode;
} handshake_priv_t;

typedef struct {
  gnutls_session_t session;
  gnutls_certificate_credentials_t credentials;
  gnutls_priority_t priority;
  handshake_priv_t handshake;
} dtls_session_t;

static const napi_type_tag dtls_session_type_tag = {
  0x82c6a5dbf795416c, 0xbe0e0c47ebbfaf18
};

static void dtls_cleanup_hook(void*);
static napi_value dtls_create_session(napi_env env, napi_callback_info cb);
static void dtls_close_session(napi_env env, void* handle, void*);
static napi_value dtls_set_mtu(napi_env env, napi_callback_info cb);
static napi_value dtls_get_mtu(napi_env env, napi_callback_info cb);
static napi_value dtls_handshake(napi_env env, napi_callback_info cb);
static void dtls_handshake_execute(napi_env env, void* data);
static void dtls_handshake_complete(napi_env env, napi_status status, void* data);

static dtls_session_t* dtls_open_handle() {
  return (dtls_session_t*) gnutls_malloc(sizeof(dtls_session_t));
}

static void dtls_close_handle(napi_env env, dtls_session_t* dtls) {
  if (dtls == NULL) return;

  if (dtls->handshake.status == dtls_async_work_executed) {
    // seg fault may be here if work completes before
    napi_cancel_async_work(env, dtls->handshake.work);
    napi_delete_async_work(env, dtls->handshake.work);
    napi_delete_reference(env, dtls->handshake.callback);
  }

  gnutls_certificate_free_credentials(dtls->credentials);
  gnutls_deinit(dtls->session);
  gnutls_free(dtls);
}

NAPI_MODULE_INIT() {
  napi_value gnutls_version, create_session, set_mtu, get_mtu, handshake;

  CALL(gnutls_global_init());

  NAPI_CALL(napi_add_env_cleanup_hook(env, dtls_cleanup_hook, NULL));

  NAPI_CALL(napi_create_string_utf8(env, GNUTLS_VERSION, NAPI_AUTO_LENGTH, &gnutls_version));
  NAPI_CALL(napi_set_named_property(env, exports, "gnutls_version", gnutls_version));

  NAPI_CALL(napi_create_function(env, NULL, 0, dtls_create_session, NULL, &create_session));
  NAPI_CALL(napi_set_named_property(env, exports, "create_session", create_session));

  NAPI_CALL(napi_create_function(env, NULL, 0, dtls_set_mtu, NULL, &set_mtu));
  NAPI_CALL(napi_set_named_property(env, exports, "set_mtu", set_mtu));

  NAPI_CALL(napi_create_function(env, NULL, 0, dtls_get_mtu, NULL, &get_mtu));
  NAPI_CALL(napi_set_named_property(env, exports, "get_mtu", get_mtu));

  NAPI_CALL(napi_create_function(env, NULL, 0, dtls_handshake, NULL, &handshake));
  NAPI_CALL(napi_set_named_property(env, exports, "handshake", handshake));

  return exports;
}

static void dtls_cleanup_hook(void* data) {
  gnutls_global_deinit();
}

// https://www.gnutls.org/manual/gnutls.html
// https://gyp.gsrc.io/docs/InputFormatReference.md

static void dtls_close_session(napi_env env, void* handle, void* hint) {
  dtls_close_handle(env, (dtls_session_t*) handle);
}

static napi_value dtls_create_session(napi_env env, napi_callback_info cb) {
  napi_value result;
  int32_t flags = 0;
  size_t argc = 1;
  napi_value argv[1];

  NAPI_CALL(napi_get_cb_info(env, cb, &argc, argv, NULL, NULL));

  if (argc == 0) {
    NAPI_THROW("Expected GnuTLS session init flags");
  }

  NAPI_CALL(napi_get_value_int32(env, argv[0], &flags));

  if (flags <= 0) {
    NAPI_THROW("Invalid GnuTLS session init flags");
  }

  dtls_session_t* dtls = dtls_open_handle();
  if (dtls == NULL) return NULL;

  CALL(gnutls_init(&dtls->session, (unsigned int)flags));
  CALL(gnutls_certificate_allocate_credentials(&dtls->credentials));
  CALL(gnutls_set_default_priority(dtls->session));
  dtls->handshake.status = dtls_async_work_init;
  dtls->handshake.errcode = 0;

  NAPI_CALL(napi_create_object(env, &result));
  NAPI_CALL(napi_type_tag_object(env, result, &dtls_session_type_tag));
  NAPI_CALL(napi_wrap(env, result, dtls, &dtls_close_session, NULL, NULL));

  return result;
}

static napi_value dtls_set_mtu(napi_env env, napi_callback_info cb) {
  int32_t mtu = 0;
  size_t argc = 2;
  napi_value argv[2], result;
  bool is_dtls_session;
  dtls_session_t* dtls;

  NAPI_CALL(napi_get_cb_info(env, cb, &argc, argv, NULL, NULL));
  if (argc < 2) {
    NAPI_THROW("Missing arguments");
  }

  NAPI_CALL(napi_check_object_type_tag(env, argv[0], &dtls_session_type_tag, &is_dtls_session));
  if (!is_dtls_session) {
    NAPI_THROW_TYPE("Invalid session handle");
  }

  NAPI_CALL(napi_get_value_int32(env, argv[1], &mtu));
  if (mtu <= 0) {
    NAPI_THROW("Invalid mtu value");
  }

  NAPI_CALL(napi_unwrap(env, argv[0], (void**)&dtls));
  gnutls_dtls_set_mtu(dtls->session, (unsigned int)mtu);

  return result;
}

static napi_value dtls_get_mtu(napi_env env, napi_callback_info cb) {
  unsigned int mtu = 0;
  size_t argc = 1;
  napi_value argv[1], result;
  bool is_dtls_session;
  dtls_session_t* dtls;

  NAPI_CALL(napi_get_cb_info(env, cb, &argc, argv, NULL, NULL));
  if (argc == 0) {
    NAPI_THROW("Missing arguments");
  }

  NAPI_CALL(napi_check_object_type_tag(env, argv[0], &dtls_session_type_tag, &is_dtls_session));
  if (!is_dtls_session) {
    NAPI_THROW_TYPE("Invalid session handle");
  }

  NAPI_CALL(napi_unwrap(env, argv[0], (void**)&dtls));
  mtu = gnutls_dtls_get_mtu(dtls->session);
  NAPI_CALL(napi_create_uint32(env, mtu, &result));

  return result;
}

static napi_value dtls_handshake(napi_env env, napi_callback_info cb) {
  size_t argc = 2;
  napi_value argv[2], result, resource_name;
  bool is_dtls_session;
  dtls_session_t* dtls;

  NAPI_CALL(napi_get_cb_info(env, cb, &argc, argv, NULL, NULL));
  if (argc < 2) {
    NAPI_THROW("Missing arguments");
  }

  NAPI_CALL(napi_check_object_type_tag(env, argv[0], &dtls_session_type_tag, &is_dtls_session));
  if (!is_dtls_session) {
    NAPI_THROW_TYPE("Invalid session handle");
  }

  NAPI_CALL(napi_unwrap(env, argv[0], (void**)&dtls));

  if (dtls->handshake.status != dtls_async_work_init) {
    NAPI_THROW("Handshake already called");
  }

  NAPI_CALL(napi_create_reference(env, argv[1], 0, &dtls->handshake.callback));
  NAPI_CALL(napi_create_string_utf8(env, "dtls::handshake", NAPI_AUTO_LENGTH, &resource_name));
  NAPI_CALL(napi_create_async_work(
                                  env,
                                  NULL,
                                  resource_name,
                                  &dtls_handshake_execute,
                                  &dtls_handshake_complete,
                                  (void*) dtls,
                                  &dtls->handshake.work
  ));
  NAPI_CALL(napi_queue_async_work(env, dtls->handshake.work));
  dtls->handshake.status = dtls_async_work_executed;

  return result;
}

static void dtls_handshake_execute(napi_env env, void* data) {
  dtls_session_t* dtls = data;

  dtls->handshake.errcode = gnutls_handshake(dtls->session);
}

static void dtls_handshake_complete(napi_env env, napi_status status, void* data) {
  dtls_session_t* dtls = data;
  napi_value callback, globalThis, message, err;
  size_t argc = 1;

  if (dtls->handshake.status != dtls_async_work_executed) {
    return;
  }

  dtls->handshake.status = dtls_async_work_completed;

  if (dtls->handshake.errcode < GNUTLS_E_SUCCESS) {
    NAPI_CALL(napi_create_string_utf8(env, gnutls_strerror(dtls->handshake.errcode), NAPI_AUTO_LENGTH, &message));
    NAPI_CALL(napi_create_error(env, NULL, message, &err));
  }
  napi_value* argv = &err;

  NAPI_CALL(napi_get_global(env, &globalThis));
  NAPI_CALL(napi_get_reference_value(env, dtls->handshake.callback, &callback));
  NAPI_CALL(napi_call_function(env, globalThis, callback, argc, argv, NULL));

  NAPI_CALL(napi_delete_async_work(env, dtls->handshake.work));
  NAPI_CALL(napi_delete_reference(env, dtls->handshake.callback));
}
