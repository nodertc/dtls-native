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

#include <node_api.h>
#include <gnutls/gnutls.h>

GNUTLS_SKIP_GLOBAL_INIT

void dtls_cleanup_hook(void*);

NAPI_MODULE_INIT() {
  napi_status status;
  napi_value gnutls_version;

  int ret = gnutls_global_init();
  if (ret != GNUTLS_E_SUCCESS) return NULL;

  status = napi_add_env_cleanup_hook(env, dtls_cleanup_hook, NULL);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "cannot set clean up hook");
  }

  status = napi_create_string_utf8(env, GNUTLS_VERSION, NAPI_AUTO_LENGTH, &gnutls_version);
  if (status != napi_ok) return NULL;

  status = napi_set_named_property(env, exports, "gnutls_version", gnutls_version);
  if (status != napi_ok) return NULL;

  return exports;
}

void dtls_cleanup_hook(void* data) {
  gnutls_global_deinit();
};

// https://www.gnutls.org/manual/gnutls.html
// https://gyp.gsrc.io/docs/InputFormatReference.md
