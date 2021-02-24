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
#include <uv.h>
#include <gnutls/gnutls.h>
#include <stdlib.h>

GNUTLS_SKIP_GLOBAL_INIT

typedef struct {
  gnutls_session_t session;
  gnutls_certificate_credentials_t credentials;
  gnutls_priority_t priority;
} dtls_session_t;

static const napi_type_tag dtls_session_type_tag = {
  0x82c6a5dbf795416c, 0xbe0e0c47ebbfaf18
};

static void dtls_cleanup_hook(void*);
static napi_value dtls_create_session(napi_env env, napi_callback_info cb);
static void dtls_close_session(napi_env env, void* handle, void*);

static dtls_session_t* dtls_open_handle() {
  return (dtls_session_t*) malloc(sizeof(dtls_session_t));
}

static void dtls_close_handle(dtls_session_t* dtls) {
  if (!dtls) return;

  gnutls_certificate_free_credentials(dtls->credentials);
  gnutls_deinit(dtls->session);
  free(dtls);
}

NAPI_MODULE_INIT() {
  napi_status status;
  napi_value gnutls_version, create_session;

  int ret = gnutls_global_init();
  if (ret != GNUTLS_E_SUCCESS) return NULL;

  status = napi_add_env_cleanup_hook(env, dtls_cleanup_hook, NULL);
  if (status != napi_ok) return NULL;

  status = napi_create_string_utf8(env, GNUTLS_VERSION, NAPI_AUTO_LENGTH, &gnutls_version);
  if (status != napi_ok) return NULL;

  status = napi_set_named_property(env, exports, "gnutls_version", gnutls_version);
  if (status != napi_ok) return NULL;

  status = napi_create_function(env, NULL, 0, dtls_create_session, NULL, &create_session);
  if (status != napi_ok) return NULL;

  status = napi_set_named_property(env, exports, "create_session", create_session);
  if (status != napi_ok) return NULL;

  return exports;
}

static void dtls_cleanup_hook(void* data) {
  gnutls_global_deinit();
}

// https://www.gnutls.org/manual/gnutls.html
// https://gyp.gsrc.io/docs/InputFormatReference.md

static void dtls_close_session(napi_env env, void* handle, void* hint) {
  dtls_close_handle((dtls_session_t*) handle);
}

static napi_value dtls_create_session(napi_env env, napi_callback_info cb) {
  napi_status status;
  napi_value result;
  int32_t flags = 0;
  size_t argc = 1;
  napi_value argv[1];
  int ret = 0;

  status = napi_get_cb_info(env, cb, &argc, argv, NULL, NULL);
  if (status != napi_ok) return NULL;

  if (argc == 0) {
    napi_throw_error(env, NULL, "Expected GnuTLS session init flags");
  }

  status = napi_get_value_int32(env, argv[0], &flags);
  if (status != napi_ok) return NULL;

  if (flags <= 0) {
    napi_throw_error(env, NULL, "Invalid GnuTLS session init flags");
  }

  dtls_session_t* dtls = dtls_open_handle();
  if (!dtls) return NULL;

  ret = gnutls_init(&dtls->session, (unsigned int)flags);
  if (ret < 0) return NULL;

  ret = gnutls_certificate_allocate_credentials(&dtls->credentials);
  if (ret < 0) return NULL;

  // wrapper
  status = napi_create_object(env, &result);
  if (status != napi_ok) return NULL;

  status = napi_type_tag_object(env, result, &dtls_session_type_tag);
  if (status != napi_ok) return NULL;

  status = napi_wrap(env, result, dtls, &dtls_close_session, NULL, NULL);
  if (status != napi_ok) return NULL;

  return result;
}
