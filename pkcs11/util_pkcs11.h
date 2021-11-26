/*
 * Copyright 2015-2018 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UTIL_PKCS11_H
#define UTIL_PKCS11_H

#include <yubihsm.h>
#include <pkcs11y.h>

#include "yubihsm_pkcs11.h"

CK_RV get_mechanism_list(yubihsm_pkcs11_slot *slot,
                         CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR count);

CK_RV get_mechanism_info(yubihsm_pkcs11_slot *slot, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo);

void destroy_session(yubihsm_pkcs11_context *ctx, CK_SESSION_HANDLE hSession);

yubihsm_pkcs11_object_desc *get_object_desc(yubihsm_pkcs11_slot *slot,
                                            CK_OBJECT_HANDLE objectHandle);

void delete_object_from_cache(yubihsm_pkcs11_slot *slot,
                              CK_OBJECT_HANDLE objHandle);

CK_RV check_sign_mechanism(yubihsm_pkcs11_slot *slot,
                           CK_MECHANISM_PTR pMechanism);

CK_RV apply_sign_mechanism_init(yubihsm_pkcs11_op_info *op_info);
CK_RV apply_sign_mechanism_update(yubihsm_pkcs11_op_info *op_info,
                                  CK_BYTE_PTR in, CK_ULONG in_len);
CK_RV apply_sign_mechanism_finalize(yubihsm_pkcs11_op_info *op_info);
CK_RV perform_signature(yh_session *session, yubihsm_pkcs11_op_info *op_info,
                        uint8_t *signature, uint16_t *signature_len);
void sign_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info);

CK_RV apply_verify_mechanism_init(yubihsm_pkcs11_op_info *op_info);
CK_RV apply_verify_mechanism_update(yubihsm_pkcs11_op_info *op_info,
                                    CK_BYTE_PTR in, CK_ULONG in_len);
CK_RV apply_verify_mechanism_finalize(yubihsm_pkcs11_op_info *op_info,
                                      CK_ULONG sig_len);
CK_RV perform_verify(yh_session *session, yubihsm_pkcs11_op_info *op_info,
                     uint8_t *signature, uint16_t signature_len);
void verify_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info);

CK_RV check_decrypt_mechanism(yubihsm_pkcs11_slot *slot,
                              CK_MECHANISM_PTR pMechanism);
CK_RV apply_decrypt_mechanism_init(yubihsm_pkcs11_op_info *op_info);
CK_RV apply_decrypt_mechanism_update(yh_session *session,
                                     yubihsm_pkcs11_op_info *op_info,
                                     CK_BYTE_PTR pEncryptedPart,
                                     CK_ULONG ulEncryptedPartLen,
                                     CK_BYTE_PTR pPart,
                                     CK_ULONG_PTR pulPartLen);
CK_RV apply_decrypt_mechanism_finalize(yh_session *session,
                                       yubihsm_pkcs11_op_info *op_info,
                                       CK_BYTE_PTR pData,
                                       CK_ULONG_PTR pulDataLen);
void decrypt_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info);

CK_RV apply_encrypt_mechanism_init(yubihsm_pkcs11_session *session,
                                   CK_MECHANISM_PTR pMechanism,
                                   CK_OBJECT_HANDLE hKey);
CK_RV apply_encrypt_mechanism_finalize(yh_session *session,
                                       yubihsm_pkcs11_op_info *op_info,
                                       CK_BYTE_PTR pEncryptedData,
                                       CK_ULONG_PTR pulEncryptedDataLen);
CK_RV perform_wrap_encrypt(yh_session *session, yubihsm_pkcs11_op_info *op_info,
                           uint8_t *plaintext, uint16_t *plaintext_len);
CK_RV perform_rsa_encrypt(yh_session *session, yubihsm_pkcs11_op_info *op_info,
                          CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR enc,
                          CK_ULONG_PTR enc_len);

CK_RV check_digest_mechanism(CK_MECHANISM_PTR pMechanism);
CK_RV apply_digest_mechanism_init(yubihsm_pkcs11_op_info *op_info);
CK_RV apply_digest_mechanism_update(yubihsm_pkcs11_op_info *op_info,
                                    CK_BYTE_PTR in, CK_ULONG in_len);
CK_RV apply_digest_mechanism_finalize(yubihsm_pkcs11_op_info *op_info);
CK_RV perform_digest(yubihsm_pkcs11_op_info *op_info, uint8_t *digest,
                     uint16_t *digest_len);
void digest_mechanism_cleanup(yubihsm_pkcs11_op_info *op_info);
CK_ULONG get_digest_bytelength(CK_MECHANISM_TYPE m);

CK_RV check_wrap_mechanism(yubihsm_pkcs11_slot *slot,
                           CK_MECHANISM_PTR pMechanism);

bool is_RSA_sign_mechanism(CK_MECHANISM_TYPE m);
bool is_RSA_decrypt_mechanism(CK_MECHANISM_TYPE m);
bool is_hashed_mechanism(CK_MECHANISM_TYPE m);
bool is_PKCS1v1_5_sign_mechanism(CK_MECHANISM_TYPE m);
bool is_ECDSA_sign_mechanism(CK_MECHANISM_TYPE m);
bool is_PSS_sign_mechanism(CK_MECHANISM_TYPE m);
bool is_HMAC_sign_mechanism(CK_MECHANISM_TYPE m);

void set_native_locking(yubihsm_pkcs11_context *ctx);
CK_RV add_connectors(yubihsm_pkcs11_context *ctx, int n_connectors,
                     char **connector_names, yh_connector **connectors);
bool delete_session(yubihsm_pkcs11_context *ctx,
                    CK_SESSION_HANDLE_PTR phSession);
CK_RV get_session(yubihsm_pkcs11_context *ctx, CK_SESSION_HANDLE hSession,
                  yubihsm_pkcs11_session **session, int session_state);
yubihsm_pkcs11_slot *get_slot(yubihsm_pkcs11_context *ctx, CK_ULONG id);
void release_slot(yubihsm_pkcs11_context *ctx, yubihsm_pkcs11_slot *slot);
bool create_session(yubihsm_pkcs11_slot *slot, CK_FLAGS flags,
                    CK_SESSION_HANDLE_PTR phSession);
void release_session(yubihsm_pkcs11_context *ctx,
                     yubihsm_pkcs11_session *session);

CK_RV set_template_attribute(yubihsm_pkcs11_attribute *attribute, void *value);
CK_RV parse_rsa_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         yubihsm_pkcs11_object_template *template);
CK_RV parse_ec_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                        yubihsm_pkcs11_object_template *template);
CK_RV parse_hmac_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                          yubihsm_pkcs11_object_template *template,
                          bool generate);
CK_RV parse_wrap_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                          yubihsm_pkcs11_object_template *template,
                          yh_algorithm algorithm, bool generate);
CK_RV parse_aes_template(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         yubihsm_pkcs11_object_template *template,
                         bool generate);

CK_RV parse_rsa_generate_template(CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                  CK_ULONG ulPublicKeyAttributeCount,
                                  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                  CK_ULONG ulPrivateKeyAttributeCount,
                                  yubihsm_pkcs11_object_template *template);

CK_RV parse_ec_generate_template(CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                 CK_ULONG ulPublicKeyAttributeCount,
                                 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                 CK_ULONG ulPrivateKeyAttributeCount,
                                 yubihsm_pkcs11_object_template *template);

int parse_id_value(void *value, CK_ULONG len);

CK_RV populate_template(int type, void *object, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulCount, yh_session *session);

CK_RV validate_derive_key_attribute(CK_ATTRIBUTE_TYPE type, void *value);

CK_RV check_bool_attribute(void *value, bool check);
CK_RV yrc_to_rv(yh_rc rc);

#endif
