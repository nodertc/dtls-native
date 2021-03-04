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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

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

static bool debugMode = false;
#define DBG(...) if (debugMode) { printf(__VA_ARGS__); printf("\n"); }
#define MAX_UDP 1500

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
  napi_threadsafe_function push_func;
  bool is_push_func_created;
  napi_threadsafe_function pull_func;
  bool is_pull_func_created;

  void* pull_data;
  size_t pull_data_allocated_length;
  size_t pull_data_awaited_length;
  size_t pull_data_offset_start;
} transport_priv_t;

typedef struct {
  gnutls_session_t session;
  gnutls_certificate_credentials_t credentials;
  gnutls_priority_t priority;
  char* priority_string;
  bool have_priority;
  handshake_priv_t handshake;
  transport_priv_t transport;
} dtls_session_t;

typedef struct {
  void* buf;
  size_t length;
} dtls_datum_t;

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
static ssize_t dtls_push_func(gnutls_transport_ptr_t ptr, const void* buf, size_t length);
static void dtls_push_func_call_js(napi_env env, napi_value cb, void* context, void* data);
static napi_value dtls_set_push_func(napi_env env, napi_callback_info cb);
static ssize_t dtls_pull_func(gnutls_transport_ptr_t ptr, void *data, size_t size);
static int dtls_pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms);
static napi_value dtls_set_debug_mode(napi_env env, napi_callback_info cb);
static napi_value dtls_set_pull_func(napi_env env, napi_callback_info cb);
static void dtls_pull_func_call_js(napi_env env, napi_value cb, void* context, void* data);
static napi_value dtls_set_priority(napi_env env, napi_callback_info cb);
static napi_value dtls_bye(napi_env env, napi_callback_info cb);

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

  if (dtls->transport.is_push_func_created) {
    napi_release_threadsafe_function(dtls->transport.push_func, napi_tsfn_abort);
  }

  if (dtls->transport.is_pull_func_created) {
    NAPI_CALL(napi_release_threadsafe_function(dtls->transport.pull_func, napi_tsfn_abort));
  }

  gnutls_free(dtls->transport.pull_data);
  gnutls_certificate_free_credentials(dtls->credentials);

  if (dtls->have_priority) {
    gnutls_free(dtls->priority_string);
    gnutls_priority_deinit(dtls->priority);
  }

  gnutls_deinit(dtls->session);
  gnutls_free(dtls);
}

NAPI_MODULE_INIT() {
  napi_value gnutls_version, create_session, set_mtu, get_mtu,
            handshake, push_func, pull_func, set_debug_mode,
            priority, bye;

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

  NAPI_CALL(napi_create_function(env, NULL, 0, dtls_set_push_func, NULL, &push_func));
  NAPI_CALL(napi_set_named_property(env, exports, "send", push_func));

  NAPI_CALL(napi_create_function(env, NULL, 0, dtls_set_debug_mode, NULL, &set_debug_mode));
  NAPI_CALL(napi_set_named_property(env, exports, "set_debug_mode", set_debug_mode));

  NAPI_CALL(napi_create_function(env, NULL, 0, dtls_set_pull_func, NULL, &pull_func));
  NAPI_CALL(napi_set_named_property(env, exports, "recv", pull_func));

  NAPI_CALL(napi_create_function(env, NULL, 0, dtls_set_priority, NULL, &priority));
  NAPI_CALL(napi_set_named_property(env, exports, "set_priority", priority));

  NAPI_CALL(napi_create_function(env, NULL, 0, dtls_bye, NULL, &bye));
  NAPI_CALL(napi_set_named_property(env, exports, "bye", bye));

  return exports;
}

static void dtls_cleanup_hook(void* data) {
  DBG("dtls: call dtls_cleanup_hook");
  gnutls_global_deinit();
}

// https://www.gnutls.org/manual/gnutls.html
// https://gyp.gsrc.io/docs/InputFormatReference.md

static void dtls_close_session(napi_env env, void* handle, void* hint) {
  DBG("dtls: call close session");
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
  CALL(gnutls_certificate_set_x509_system_trust(dtls->credentials));
  CALL(gnutls_credentials_set(dtls->session, GNUTLS_CRD_CERTIFICATE, dtls->credentials));
  CALL(gnutls_set_default_priority(dtls->session));

  gnutls_session_set_ptr(dtls->session, dtls);
  gnutls_transport_set_ptr(dtls->session, dtls);

  gnutls_transport_set_push_function(dtls->session, dtls_push_func);
  gnutls_transport_set_pull_function(dtls->session, dtls_pull_func);
  gnutls_transport_set_pull_timeout_function(dtls->session, dtls_pull_timeout_func);

  dtls->handshake.status = dtls_async_work_init;
  dtls->handshake.errcode = 0;
  dtls->transport.is_push_func_created = false;

  dtls->transport.pull_data_awaited_length = 0;
  dtls->transport.pull_data_offset_start = 0;
  dtls->transport.pull_data = gnutls_malloc(MAX_UDP);
  dtls->transport.pull_data_allocated_length = MAX_UDP;
  dtls->transport.is_pull_func_created = false;

  dtls->have_priority = false;

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
  DBG("dtls: start handshake polling");

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
  DBG("dtls: execute handshake worker");
  dtls_session_t* dtls = data;
  int err = 0;

  do {
    err = gnutls_handshake(dtls->session);
  } while (err == GNUTLS_E_INTERRUPTED || err == GNUTLS_E_AGAIN);

  dtls->handshake.errcode = err;
}

static void dtls_handshake_complete(napi_env env, napi_status status, void* data) {
  DBG("dtls: complete handshake worker");

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
  } else {
    argc = 0;
  }
  napi_value* argv = &err;

  NAPI_CALL(napi_get_global(env, &globalThis));
  NAPI_CALL(napi_get_reference_value(env, dtls->handshake.callback, &callback));
  NAPI_CALL(napi_call_function(env, globalThis, callback, argc, argv, NULL));

  NAPI_CALL(napi_delete_async_work(env, dtls->handshake.work));
  NAPI_CALL(napi_delete_reference(env, dtls->handshake.callback));
}

static ssize_t dtls_push_func(gnutls_transport_ptr_t ptr, const void* buf, size_t length) {
  DBG("dtls: call push_func");

  dtls_session_t* dtls = ptr;
  dtls_datum_t* data = (dtls_datum_t*) gnutls_malloc(sizeof(dtls_datum_t));
  napi_status status;

  data->length = length;
  data->buf = gnutls_malloc(length);
  memcpy(data->buf, buf, length);

  status = napi_acquire_threadsafe_function(dtls->transport.push_func);
  if (status != napi_ok) goto release;

  status = napi_call_threadsafe_function(dtls->transport.push_func, (void*)data, napi_tsfn_blocking);
  if (status != napi_ok) goto release;

  status = napi_release_threadsafe_function(dtls->transport.push_func, napi_tsfn_release);
  if (status != napi_ok) goto exit; // do not need to free memory, callback pushed to the queue

  if (status != napi_ok) {
  release:
    gnutls_free(data->buf);
    gnutls_free(data);
  exit:
    DBG("dtls: push_func failed");
    return GNUTLS_E_PUSH_ERROR;
  }

  DBG("dtls: complete push_func");
  return length;
}

static void dtls_push_func_call_js(napi_env env, napi_value cb, void* context, void* data) {
  DBG("dtls: call push_func_call_js");

  dtls_datum_t* packet = data;
  napi_value buffer, globalThis;
  size_t argc = 1;

  NAPI_CALL(napi_create_buffer_copy(env, packet->length, packet->buf, NULL, &buffer));

  gnutls_free(packet->buf);
  gnutls_free(packet);

  napi_value* argv = &buffer;
  NAPI_CALL(napi_get_global(env, &globalThis));
  NAPI_CALL(napi_call_function(env, globalThis, cb, argc, argv, NULL));
}

static napi_value dtls_set_push_func(napi_env env, napi_callback_info cb) {
  DBG("dtls: set push_func");
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

  // TODO: what is initial_thread_count and max_queue_size
  // TODO: how to clearly release
  NAPI_CALL(napi_create_string_utf8(env, "dtls::push_func", NAPI_AUTO_LENGTH, &resource_name));
  NAPI_CALL(napi_create_threadsafe_function(
                                            env,
                                            argv[1],
                                            NULL,
                                            resource_name,
                                            0,
                                            1, // Once the number of threads making use of
                                               // a napi_threadsafe_function reaches zero, no further threads
                                               // can start making use of it.
                                            NULL,
                                            NULL,
                                            (void*)dtls,
                                            dtls_push_func_call_js,
                                            &dtls->transport.push_func
  ));
  dtls->transport.is_push_func_created = true;

  return result;
}

static ssize_t dtls_pull_func(gnutls_transport_ptr_t ptr, void *data, size_t size) {
  dtls_session_t* dtls = ptr;
  size_t length = 0;
  napi_status status;


  if (dtls->transport.pull_data_offset_start >= dtls->transport.pull_data_awaited_length && dtls->transport.pull_data_awaited_length > 0) {
    goto again;
  }

  if (dtls->transport.pull_data_awaited_length == 0) {
  again:
    DBG("dtls: call pull_func, no data available");
    gnutls_transport_set_errno(dtls->session, EAGAIN);
    return -1;
  }

  if (size >= dtls->transport.pull_data_awaited_length) {
    length = dtls->transport.pull_data_awaited_length;
    dtls->transport.pull_data_offset_start = length; // to disable repeated reads, wait for callback
    memcpy(data, dtls->transport.pull_data, length);

    DBG("dtls: call pull_func, %d bytes readed", length);
  } else {
    int remainder = dtls->transport.pull_data_awaited_length - dtls->transport.pull_data_offset_start;
    if (remainder <= 0) goto callback;
    size_t copy_length = remainder > size ? size : remainder;

    assert((copy_length + dtls->transport.pull_data_offset_start)<=dtls->transport.pull_data_allocated_length);
    memcpy(data, dtls->transport.pull_data + dtls->transport.pull_data_offset_start, copy_length);

    dtls->transport.pull_data_offset_start += copy_length;
    length = copy_length;

    DBG("dtls: call pull_func, %d of %d bytes readed", dtls->transport.pull_data_offset_start, dtls->transport.pull_data_awaited_length);

    if (dtls->transport.pull_data_offset_start < dtls->transport.pull_data_awaited_length) goto exit;
  }

callback:
  DBG("dtls: call pull_func, enqueue callback");

  status = napi_acquire_threadsafe_function(dtls->transport.pull_func);
  if (status != napi_ok) goto release;

  status = napi_call_threadsafe_function(dtls->transport.pull_func, NULL, napi_tsfn_blocking);
  if (status != napi_ok) goto release;

  status = napi_release_threadsafe_function(dtls->transport.pull_func, napi_tsfn_release);
  if (status != napi_ok) {
  release:
    DBG("dtls: call pull_func, failed to enqueue callback");
    gnutls_transport_set_errno(dtls->session, EIO);
    return -1;
  }

exit:
  return length;
}

static napi_value dtls_set_debug_mode(napi_env env, napi_callback_info cb) {
  size_t argc = 1;
  napi_value argv[1];

  NAPI_CALL(napi_get_cb_info(env, cb, &argc, argv, NULL, NULL));
  if (argc == 0) {
    NAPI_THROW("Missing arguments");
  }

  NAPI_CALL(napi_get_value_bool(env, argv[0], &debugMode));
  return NULL;
}

static int dtls_pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms) {
  dtls_session_t* dtls = ptr;

  size_t size = dtls->transport.pull_data_awaited_length - dtls->transport.pull_data_offset_start;

  if (size > 0) {
    DBG("dtls: call pull_timeout_func, wait for %d bytes to read", size);
  }

  return size;
}

static napi_value dtls_set_pull_func(napi_env env, napi_callback_info cb) {
  DBG("dtls: set read func");
  size_t argc = 3, length;
  napi_value argv[3], result, resource_name;
  bool is_dtls_session, is_buffer;
  dtls_session_t* dtls;
  napi_valuetype is_callback;
  void* buffer;

  NAPI_CALL(napi_get_cb_info(env, cb, &argc, argv, NULL, NULL));
  if (argc < 3) {
    NAPI_THROW("Missing arguments");
  }

  NAPI_CALL(napi_check_object_type_tag(env, argv[0], &dtls_session_type_tag, &is_dtls_session));
  if (!is_dtls_session) {
    NAPI_THROW_TYPE("Invalid session handle");
  }

  NAPI_CALL(napi_unwrap(env, argv[0], (void**)&dtls));

  NAPI_CALL(napi_is_buffer(env, argv[1], &is_buffer));
  if (!is_buffer) {
    NAPI_THROW_TYPE("Argument #2 should be a Buffer");
  }

  NAPI_CALL(napi_typeof(env, argv[2], &is_callback));
  if (is_callback != napi_function) {
    NAPI_THROW_TYPE("Argument #3 should be a Function");
  }

  NAPI_CALL(napi_get_buffer_info(env, argv[1], &buffer, &length));
  if (length > dtls->transport.pull_data_allocated_length) {
    NAPI_THROW("Invalid buffer size");
  }

  memcpy(dtls->transport.pull_data, buffer, length);
  dtls->transport.pull_data_awaited_length = length;
  dtls->transport.pull_data_offset_start = 0;

  if (dtls->transport.is_pull_func_created) {
    NAPI_CALL(napi_release_threadsafe_function(dtls->transport.pull_func, napi_tsfn_abort));
    dtls->transport.is_pull_func_created = false;
  }

  NAPI_CALL(napi_create_string_utf8(env, "dtls::pull_func", NAPI_AUTO_LENGTH, &resource_name));
  NAPI_CALL(napi_create_threadsafe_function(
                                            env,
                                            argv[2],
                                            NULL,
                                            resource_name,
                                            0,
                                            1, // Once the number of threads making use of
                                               // a napi_threadsafe_function reaches zero, no further threads
                                               // can start making use of it.
                                            NULL,
                                            NULL,
                                            (void*)dtls,
                                            dtls_pull_func_call_js,
                                            &dtls->transport.pull_func
  ));
  dtls->transport.is_pull_func_created = true;

  return result;
}

static void dtls_pull_func_call_js(napi_env env, napi_value cb, void* context, void* data) {
  DBG("dtls: call read callback");

  dtls_session_t* dtls = context;
  napi_value argv, globalThis;
  size_t argc = 0;

  NAPI_CALL(napi_get_global(env, &globalThis));
  NAPI_CALL(napi_call_function(env, globalThis, cb, argc, &argv, NULL));

  dtls->transport.pull_data_awaited_length = 0;
  dtls->transport.pull_data_offset_start = 0;

  if (dtls->transport.is_pull_func_created) {
    NAPI_CALL(napi_release_threadsafe_function(dtls->transport.pull_func, napi_tsfn_abort));
    dtls->transport.is_pull_func_created = false;
  }
}

static napi_value dtls_set_priority(napi_env env, napi_callback_info cb) {
  DBG("dtls: set_priority");
  size_t argc = 2, length, bufsize = 100;
  napi_value argv[2], result;
  bool is_dtls_session;
  dtls_session_t* dtls;
  napi_valuetype is_string;

  NAPI_CALL(napi_get_cb_info(env, cb, &argc, argv, NULL, NULL));
  if (argc < 2) {
    NAPI_THROW("Missing arguments");
  }

  NAPI_CALL(napi_check_object_type_tag(env, argv[0], &dtls_session_type_tag, &is_dtls_session));
  if (!is_dtls_session) {
    NAPI_THROW_TYPE("Invalid session handle");
  }

  NAPI_CALL(napi_unwrap(env, argv[0], (void**)&dtls));

  NAPI_CALL(napi_typeof(env, argv[1], &is_string));
  if (is_string != napi_string) {
    NAPI_THROW_TYPE("Argument #2 should be a String");
  }

  if (dtls->have_priority) {
    gnutls_free(dtls->priority_string);
  }

  dtls->priority_string = (char*)gnutls_malloc(bufsize);
  NAPI_CALL(napi_get_value_string_latin1(env, argv[1], dtls->priority_string, bufsize, &length));

  CALL(gnutls_priority_init2(&dtls->priority, dtls->priority_string, NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND));
  CALL(gnutls_priority_set(dtls->session, dtls->priority));
  dtls->have_priority = true;

  return result;
}

static napi_value dtls_bye(napi_env env, napi_callback_info cb) {
  DBG("dtls: gnutls_bye");
  size_t argc = 1;
  napi_value argv[1], result;
  bool is_dtls_session;
  dtls_session_t* dtls;

  NAPI_CALL(napi_get_cb_info(env, cb, &argc, argv, NULL, NULL));
  if (argc < 1) {
    NAPI_THROW("Missing arguments");
  }

  NAPI_CALL(napi_check_object_type_tag(env, argv[0], &dtls_session_type_tag, &is_dtls_session));
  if (!is_dtls_session) {
    NAPI_THROW_TYPE("Invalid session handle");
  }

  NAPI_CALL(napi_unwrap(env, argv[0], (void**)&dtls));

  CALL(gnutls_bye(dtls->session, GNUTLS_SHUT_WR));

  return result;
}
