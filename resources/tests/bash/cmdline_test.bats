load 'test_helper/bats-support/load'
load 'test_helper/bats-assert/load'

setup_file() {
  
  echo "--- Configuration via Environment Variables ---" >&3
  echo "YUBIHSM_PATH: path to the yubihsm-shell command line tool - using default connector" >&3
  echo "SPECIFIED_CONNECTOR: path to the yubihsm-shell command line tool - using specified connector" >&3
  echo "TESTS: which tests to run. Possible values are: 'short', 'medium' or 'all'" >&3
  echo "It is also possible to individually enable tests by setting the environment variables specified in the README file to 'true'" >&3
  echo "-----------------------------------------------" >&3
   
  case "$TESTS" in
  "all")
    ED_KEY_TESTS="true"
    EC_KEY_TESTS="true"
    RSA_KEY_TESTS="true"
    HMAC_KEY_TESTS="true"
    OTP_AEAD_TESTS="true"
    TEMPLATE_TESTS="true"
    WRAP_KEY_TESTS="true"
    LIST_TESTS="true"
    LABEL_TESTS="true"
    AUTHENTICATION_TESTS="true"
    ;;
  "medium")
    ED_KEY_TESTS="true"
    EC_KEY_TESTS="true"
    HMAC_KEY_TESTS="true"
    OTP_AEad_TESTS="true"
    TEMPLATE_TESTS="true"
    LIST_TESTS="true"
    LABEL_TESTS="true"
    AUTHENTICATION_TESTS="true"
    ;;
  "short")
    HMAC_KEY_TESTS="true"
    OTP_AEAD_TESTS="true"
    TEMPLATE_TESTS="true"
    LIST_TESTS="true"
    LABEL_TESTS="true"
    AUTHENTICATION_TESTS="true"
    ;;
  *)
    echo "---------------------------------------------------" >&3
    echo "Warning: Unrecognized TEST level: '$TESTS'" >&3
    echo "Ignore if you are setting individual test variables" >&3
    echo "---------------------------------------------------" >&3
    ;;
  esac

  export ED_KEY_TESTS=${ED_KEY_TESTS:-"false"}
  export EC_KEY_TESTS=${EC_KEY_TESTS:-"false"}
  export RSA_KEY_TESTS=${RSA_KEY_TESTS:-"false"}
  export HMAC_KEY_TESTS=${HMAC_KEY_TESTS:-"false"}
  export OTP_AEAD_TESTS=${OTP_AEAD_TESTS:-"false"}
  export TEMPLATE_TESTS=${TEMPLATE_TESTS:-"false"}
  export WRAP_KEY_TESTS=${WRAP_KEY_TESTS:-"false"}
  export LIST_TESTS=${LIST_TESTS:-"false"}
  export LABEL_TESTS=${LABEL_TESTS:-"false"}
  export AUTHENTICATION_TESTS=${AUTHENTICATION_TESTS:-"false"}

  local default_bin_path="yubihsm-shell"
  local os=$(uname -o) 
  export c_var=""

  if [[ "$os" == "Msys" ]]; then
    default_bin_path="C:\Program Files\Yubico\YubiHSM Shell\bin\yubihsm-shell.exe"
    export MSYS2_ARG_CONV_EXCL=* # To prevent path conversion by MSYS2
  elif [[ "$os" == "GNU/Linux" || "$os" == "Darwin" ]]; then
    default_bin_path="/usr/local/bin/yubihsm-shell"
  fi

  if [ -n "$SPECIFIED_CONNECTOR" ]; then
    echo "Specified connector exists" >&3
    c_var="-C"
  fi
  export BIN=${YUBIHSM_PATH:-$default_bin_path}
  export SPECIFIED_CONNECTOR=${SPECIFIED_CONNECTOR:-""}

  echo "Variables Check:" >&3
  echo "YubiHSM-shell: $BIN" >&3
  echo "Connector: "$c_var" "$SPECIFIED_CONNECTOR"" >&3
  echo "Tests to run: $TESTS" >&3

  echo "These tests will reset your HSM" >&3
  echo "Press Enter to continue or Ctrl-C + enter to abort" >&3
  read -p ""

  if [ -e yubihsm-shell_test_dir ]; then
    rm -rf yubihsm-shell_test_dir
  fi
  mkdir yubihsm-shell_test_dir; cd yubihsm-shell_test_dir
  echo test signing data > data.txt
}

@test "Test basic functions and get Pseudo-Random" {
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")

  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"
  sleep 3
  
  run "${command_args[@]}" --version
    assert_success "Version works"

  run "${command_args[@]}" --help
    assert_success "Help works"
  
  run "${command_args[@]}" -a get-device-info  
    assert_success "Get device info"
    assert_output --partial "Serial number:"

  run "${command_args[@]}" -p password -a blink
    assert_success "Blink works"
  
  run "${command_args[@]}" -p password -a blink --duration=5
    assert_success "Blink with duration works"

  run "${command_args[@]}" -p password -a get-pseudo-random
    assert_success
    output_data=$(echo "$output" | tail -n 1)
    local byte_count
    byte_count=$(echo -n "$output_data" | wc -c | xargs)
    assert_equal "$byte_count" 512

  run "${command_args[@]}" -p password -a get-pseudo-random --out=random.txt
    assert_success "Get Pseudo-Random to file"

  length=$(cat random.txt | wc -c)
  if [ "$length" -ne 512 ]; then
    echo "Expected 512 but was "$length" characters. Without specifying byte count, 256 bytes (=512 characters) pseudo random number should have been produced." >&3
    exit 1
  fi
  rm random.txt

  run "${command_args[@]}" -p password -a get-pseudo-random --count=10
    assert_success "Get pseudo-random with --count=10"
    output_data=$(echo "$output" | tail -n 1)
    local byte_count
    byte_count=$(echo -n "$output_data" | wc -c | xargs)
    assert_equal "$byte_count" 20

  run "${command_args[@]}" -p password -a get-pseudo-random --count=10 --out=random.txt
    assert_success "Get pseudo-random with --count=10"
    length=$(cat random.txt | wc -c)
    if [ "$length" -ne 20 ]; then
      echo "Expected 20 but was "$length" characters." >&3
      exit 1
    fi
    rm random.txt
}

@test "ED Key tests" {
  [[ "$ED_KEY_TESTS" == "true" ]] || skip "skipping right now"
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")

  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"
  sleep 3

  #Generate
  run "${command_args[@]}" -p password -a generate-asymmetric-key -i 100 -l \"edKey\" -d 1,2,3 -c sign-eddsa -A ed25519
    assert_success "Generate key"
  run "${command_args[@]}" -p password -a get-object-info -i 100 -t asymmetric-key
    assert_success "get-object-info"
    assert_output --partial "id: 0x0064" 
    assert_output --partial "type: asymmetric-key" 
    assert_output --partial "algorithm: ed25519" 
    assert_output --partial 'label: ""edKey""' 
    assert_output --partial "domains: 1:2:3"
    assert_output --partial "origin: generated"
    assert_output --partial "capabilities: sign-eddsa"

  #Get public key
  run "${command_args[@]}" -p password -a get-public-key -i 100
    assert_success "Get public key"
  "${command_args[@]}" -p password -a get-public-key -i 100 > edkey1.pub 2>/dev/null
  run "${command_args[@]}" -p password -a get-public-key -i 100 --out edkey2.pub
    assert_success "Get public key to file"
  local content1
  local content2
  content1=$(tr -d '\r' < edkey1.pub)
  content2=$(tr -d '\r' < edkey2.pub)
  assert_equal "$content1" "$content2"

  #Signing
  run "${command_args[@]}" -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt
    assert_success "Sign to stdout"
  "${command_args[@]}" -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt > data.ed1.sig 2>/dev/null
  run "${command_args[@]}" -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt --out data.ed2.sig
    assert_success "Sign to file"
  content1=$(tr -d '[:space:]' < data.ed1.sig)
  content2=$(tr -d '[:space:]' < data.ed2.sig)
  assert_equal "$content1" "$content2"

  #Generating CSR
  run "${command_args[@]}" -p password -a generate-csr -i 100 -S /CN=test/ --out csr.pem
    assert_success "Generate CSR with yubihsm-shell"
  run openssl req -in csr.pem -verify
    assert_success "Verify CSR with openssl"
  
  #Delete
  run "${command_args[@]}" -p password -a delete-object -i 100 -t asymmetric-key
    assert_success "Delete key"

  run rm csr.pem
    assert_success "Remove CSR"
}

@test "EC Key tests" {
  [[ "$EC_KEY_TESTS" == "true" ]] || skip "skipping right now"
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")
  genkey=100
  import_key=200
  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"  
  sleep 3

  EC_ALGOS=("ecp224" "ecp256" "ecp384" "ecp521" "eck256")
  EC_CURVES=("secp224r1" "secp256r1" "secp384r1" "secp521r1" "secp256k1")
  if ! grep -q 'Fedora' /etc/os-release 2>/dev/null; then
    EC_ALGOS+=("ecbp256" "ecbp384" "ecbp512")
    EC_CURVES+=("brainpoolP256r1" "brainpoolP384r1" "brainpoolP512r1")
  fi

  for i in "${!EC_ALGOS[@]}"; do
    algo=${EC_ALGOS[i]}
    curve=${EC_CURVES[i]}
    echo "Testing $algo with curve $curve" >&3

    #Generate Key
    run "${command_args[@]}" -p password -a generate-asymmetric-key -i "$genkey" -l \"ecKey\" -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A "$algo"
      assert_success "Generate key"
    run "${command_args[@]}" -p password -a get-object-info -i "$genkey" -t asymmetric-key
      assert_success "get-object-info"
      assert_output --partial "id: 0x0064" 
      assert_output --partial "type: asymmetric-key" 
      assert_output --partial "algorithm: "$algo"" 
      assert_output --partial 'label: ""ecKey""' 
      assert_output --partial "domains: 5:8:13"          
      assert_output --partial "origin: generated"
      assert_output --partial "capabilities: derive-ecdh:sign-attestation-certificate:sign-ecdsa"
    run "${command_args[@]}" -p password -a get-public-key -i "$genkey" --outformat=PEM --out "$algo"-gen.pubkey
      assert_success "Get public key"
        
    #Import Key
    run openssl ecparam -genkey -name "$curve" -noout -out "$curve"-keypair.pem          
      assert_success "Generate key with openssl"
    run "${command_args[@]}" -p password -a put-asymmetric-key -i "$import_key" -l "ecKeyImport" -d "2,6,7" -c "sign-ecdsa,sign-attestation-certificate" --in="$curve"-keypair.pem
      assert_success "Import $algo key"
    run "${command_args[@]}" -p password -a get-object-info -i "$import_key" -t asymmetric-key
      assert_success "get-object-info"
      assert_output --partial "id: 0x00c8" 
      assert_output --partial "type: asymmetric-key" 
      assert_output --partial "algorithm: "$algo"" 
      assert_output --partial 'label: "ecKeyImport"' 
      assert_output --partial "domains: 2:6:7"
      assert_output --partial "origin: imported"
      assert_output --partial "capabilities: sign-attestation-certificate:sign-ecdsa"
    run "${command_args[@]}" -p password -a get-public-key -i "$import_key" --outformat=PEM --out "$algo"-import.pubkey
      assert_success "Get public key"
        
    #Signing
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$genkey" -A ecdsa-sha1 --in data.txt --outformat=PEM --out data."$algo"-sha1gen.sig
      assert_success "Sign with generated key and ecdsa-sha1"
    run openssl dgst -sha1 -verify "$algo"-gen.pubkey -signature data."$algo"-sha1gen.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$genkey" -A ecdsa-sha256 --in data.txt --outformat=PEM --out data."$algo"-sha256gen.sig
      assert_success "Sign with generated key and ecdsa-sha256"
    run openssl dgst -sha256 -verify "$algo"-gen.pubkey -signature data."$algo"-sha256gen.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$genkey" -A ecdsa-sha384 --in data.txt --outformat=PEM --out data."$algo"-sha384gen.sig
      assert_success "Sign with generated key and ecdsa-sha384"
    run openssl dgst -sha384 -verify "$algo"-gen.pubkey -signature data."$algo"-sha384gen.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$genkey" -A ecdsa-sha512 --in data.txt --outformat=PEM --out data."$algo"-sha512gen.sig
      assert_success "Sign with generated key and ecdsa-sha512"
    run openssl dgst -sha512 -verify "$algo"-gen.pubkey -signature data."$algo"-sha512gen.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$import_key" -A ecdsa-sha1 --in data.txt --outformat=PEM --out data."$algo"-sha1import.sig
      assert_success "Sign with imported key and ecdsa-sha1"
    run openssl dgst -sha1 -verify "$algo"-import.pubkey -signature data."$algo"-sha1import.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$import_key" -A ecdsa-sha256 --in data.txt --outformat=PEM --out data."$algo"-sha256import.sig
      assert_success "Sign with imported key and ecdsa-sha256"
    run openssl dgst -sha256 -verify "$algo"-import.pubkey -signature data."$algo"-sha256import.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$import_key" -A ecdsa-sha384 --in data.txt --outformat=PEM --out data."$algo"-sha384import.sig
      assert_success "Sign with imported key and ecdsa-sha384"
    run openssl dgst -sha384 -verify "$algo"-import.pubkey -signature data."$algo"-sha384import.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$import_key" -A ecdsa-sha512 --in data.txt --outformat=PEM --out data."$algo"-sha512import.sig
      assert_success "Sign with imported key and ecdsa-sha512"
    run openssl dgst -sha512 -verify "$algo"-import.pubkey -signature data."$algo"-sha512import.sig data.txt
      assert_success "Verify signature with openssl"
        
    #Get attestation certificate and selfsigned certificate
    if "${command_args[@]}" -p password -a sign-attestation-certificate -i "$genkey" --attestation-id 0 2>&1 > /dev/null;then # Some YubiHSMs does not have default attestation certificate
      run "${command_args[@]}" -p password -a sign-attestation-certificate -i "$genkey" --attestation-id 0 --out cert.pem
        assert_success "Sign attestation cert with default key"
      run openssl x509 -in cert.pem -out cert.der -outform DER
        assert_success "Convert cert format"
      run "${command_args[@]}" -p password -a put-opaque -i "$genkey" -l template_cert -A opaque-x509-certificate --in cert.der
        assert_success "Import attestation cert as template cert (same ID as generated key)"
      run "${command_args[@]}" -p password -a put-opaque -i "$import_key" -l template_cert -A opaque-x509-certificate --in cert.der
        assert_success "Import attestation cert as template cert (same ID as imported key)"
      run rm cert.der
        assert_success "Remove der cert"
    else
      run "${command_args[@]}" -p password -a put-opaque -i "$genkey" -l template_cert_gen -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem
        assert_success "Import attestation cert as template cert (same ID as generated key)"
      run "${command_args[@]}" -p password -a put-opaque -i "$import_key" -l template_cert_imp -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem
        assert_success "Import attestation cert as template cert (same ID as imported key)"
    fi

    run "${command_args[@]}" -p password -a sign-attestation-certificate -i "$genkey" --attestation-id="$genkey" --out selfsigned_cert.pem
      assert_success "Get selfsigned certificate"
    run "${command_args[@]}" -p password -a delete-object -i "$genkey" -t opaque
      assert_success "Delete template certificate"
    run "${command_args[@]}" -p password -a put-opaque -i "$genkey" -l java_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem
      assert_success "Import selfsigned with same key ID"
    run rm selfsigned_cert.pem
      assert_success "Remove selfsigned cert"

    #Sign attestation certificate
    run "${command_args[@]}" -p password -a sign-attestation-certificate -i "$genkey" --attestation-id="$import_key" --out selfsigned_cert.pem
      assert_success "Sign attestation cert with imported key"
    run "${command_args[@]}" -p password -a delete-object -i "$genkey" -t opaque
      assert_success "Delete template certificate"
    run "${command_args[@]}" -p password -a delete-object -i "$import_key" -t opaque
      assert_success "Delete template certificate"
    run rm selfsigned_cert.pem
      assert_success "Remove selfsigned cert"

    #Derive ECDH
    run openssl ec -in "$curve"-keypair.pem -pubout -out "$curve"-pubkey.pem
      assert_success "Get imported key public key with OpenSSL"
    run "${command_args[@]}" -p password -a derive-ecdh -i "$genkey" --in "$curve"-pubkey.pem --outformat binary --out "$algo"-ecdh-shell.key
      assert_success "Derive ECDH key with yubihsm-shell"
    run openssl pkeyutl -derive -inkey "$curve"-keypair.pem -peerkey "$algo"-gen.pubkey -out "$algo"-ecdh-openssl.key
      assert_success "Derive ECDH key with OpenSSL"
    run cmp "$algo"-ecdh-shell.key "$algo"-ecdh-openssl.key
      assert_success "Compare derived keys"

    #make PKCS10 certificate signing request
    run "${command_args[@]}" -p password -a generate-csr -i "$genkey" -S /CN=test/ --out csr.pem
      assert_success "Generate CSR with yubihsm-shell"
    run openssl req -in csr.pem -verify
      assert_success "Verify CSR with openssl"
    run rm csr.pem
      assert_success "Remove CSR"

    #Clean up
    run "${command_args[@]}" -p password -a delete-object -i "$genkey" -t asymmetric-key
      assert_success "Delete generated key"
    run "${command_args[@]}" -p password -a delete-object -i "$import_key" -t asymmetric-key
      assert_success "Delete imported key"
  done
}

@test "RSA Key tests" {
  [[ "$RSA_KEY_TESTS" == "true" ]] || skip "skipping right now"
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")
  RSA_KEYSIZE=("2048" "3072" "4096")

  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"
  sleep 3

  for k in ${RSA_KEYSIZE[@]}; do
    echo "Testing RSA "$k" key" >&3
    if [ "$k" -ne "2048" ]; then
      echo "This may take a while..." >&3
    fi
    #Generate Key
    run "${command_args[@]}" -p password -a generate-asymmetric-key -i 0 -l rsaKey -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate -A rsa"$k"
      assert_success "Generate RSA "$k" key"

    keyid=$(echo "$output" | tail -n 1 | awk '{print $4}')
    run "${command_args[@]}" -p password -a get-object-info -i "$keyid" -t asymmetric-key
      assert_success "get-object-info"
      assert_output --partial "id: "$keyid"" 
      assert_output --partial "type: asymmetric-key" 
      assert_output --partial "algorithm: rsa"$k"" 
      assert_output --partial "label: \"rsaKey\""
      assert_output --partial "domains: 1"
      assert_output --partial "origin: generated"
      assert_output --partial "decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss"
    run "${command_args[@]}" -p password -a get-public-key -i "$keyid" --outformat=PEM --out pubkey_rsa"$k".pem
      assert_success "Get public key"

    #Import key
    run openssl genrsa -out rsa"$k"-keypair.pem "$k"
      assert_success "Generate key with OpenSSL"
    run "${command_args[@]}" "${command_args[@]}" -p password -a put-asymmetric-key -i 0 -l rsaKeyImport -d 2 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate --in=rsa"$k"-keypair.pem
      assert_success "Import key"

    import_keyid=$(echo "$output" | tail -n 1 | awk '{print $4}')
    run "${command_args[@]}" -p password -a get-object-info -i "$import_keyid" -t asymmetric-key
      assert_success "get-object-info"
      assert_output --partial "id: "$import_keyid"" 
      assert_output --partial "type: asymmetric-key" 
      assert_output --partial "algorithm: rsa"$k"" 
      assert_output --partial "label: \"rsaKeyImport\""
      assert_output --partial "domains: 2"
      assert_output --partial "origin: imported"
      assert_output --partial "decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss"
    
    run "${command_args[@]}" -p password -a get-public-key -i "$import_keyid" --outformat=PEM --out pubkey_rsa"$k".imported.pem
      assert_success "Get public key"

    #Signing with generated key
    run "${command_args[@]}" -p password -a sign-pkcs1v15 -i "$keyid" -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data."$k"-pkcs1sha1gen.sig
      assert_success "Sign with rsa-pkcs1-sha1"
    run openssl dgst -sha1 -verify pubkey_rsa"$k".pem -signature data."$k"-pkcs1sha1gen.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pkcs1v15 -i "$keyid" -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data."$k"-pkcs1sha256gen.sig
      assert_success "Sign with rsa-pkcs1-sha256"
    run openssl dgst -sha256 -verify pubkey_rsa"$k".pem -signature data."$k"-pkcs1sha256gen.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pkcs1v15 -i "$keyid" -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data."$k"-pkcs1sha384gen.sig
      assert_success "Sign with rsa-pkcs1-sha384"
    run openssl dgst -sha384 -verify pubkey_rsa"$k".pem -signature data."$k"-pkcs1sha384gen.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pkcs1v15 -i "$keyid" -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data."$k"-pkcs1sha512gen.sig
      assert_success "Sign with rsa-pkcs1-sha512"
    run openssl dgst -sha512 -verify pubkey_rsa"$k".pem -signature data."$k"-pkcs1sha512gen.sig data.txt
      assert_success "Verify signature with openssl"


    run "${command_args[@]}" -p password -a sign-pss -i "$keyid" -A rsa-pss-sha1 --in data.txt --outformat binary --out data."$k"-psssha1gen.sig
      assert_success "Sign with rsa-pss-sha1"
    run openssl dgst -sha1 -binary -out data.sha1 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha1 -sigfile data."$k"-psssha1gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pss -i "$keyid" -A rsa-pss-sha256 --in data.txt --outformat binary --out data."$k"-psssha256gen.sig
      assert_success "Sign with rsa-pss-sha256"
    run openssl dgst -sha256 -binary -out data.sha256 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha256 -sigfile data."$k"-psssha256gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pss -i "$keyid" -A rsa-pss-sha384 --in data.txt --outformat binary --out data."$k"-psssha384gen.sig
      assert_success "Sign with rsa-pss-sha384"
    run openssl dgst -sha384 -binary -out data.sha384 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha384 -sigfile data."$k"-psssha384gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha384
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pss -i "$keyid" -A rsa-pss-sha512 --in data.txt --outformat binary --out data."$k"-psssha512gen.sig
      assert_success "Sign with rsa-pss-sha512"
    run openssl dgst -sha512 -binary -out data.sha512 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha512 -sigfile data."$k"-psssha512gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha512
      assert_success "Verify signature with openssl"
    
    #Signing with imported key
    run "${command_args[@]}" -p password -a sign-pkcs1v15 -i "$import_keyid" -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data."$k"-pkcs1sha1import.sig
      assert_success "Sign with rsa-pkcs1-sha1"
    run openssl dgst -sha1 -verify pubkey_rsa"$k".imported.pem -signature data."$k"-pkcs1sha1import.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pkcs1v15 -i "$import_keyid" -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data."$k"-pkcs1sha256import.sig
      assert_success "Sign with rsa-pkcs1-sha256"
    run openssl dgst -sha256 -verify pubkey_rsa"$k".imported.pem -signature data."$k"-pkcs1sha256import.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pkcs1v15 -i "$import_keyid" -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data."$k"-pkcs1sha384import.sig
      assert_success "Sign with rsa-pkcs1-sha384"
    run openssl dgst -sha384 -verify pubkey_rsa"$k".imported.pem -signature data."$k"-pkcs1sha384import.sig data.txt
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pkcs1v15 -i "$import_keyid" -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data."$k"-pkcs1sha512import.sig
      assert_success "Sign with rsa-pkcs1-sha512"
    run openssl dgst -sha512 -verify pubkey_rsa"$k".imported.pem -signature data."$k"-pkcs1sha512import.sig data.txt
      assert_success "Verify signature with openssl"

    run "${command_args[@]}" -p password -a sign-pss -i "$import_keyid" -A rsa-pss-sha1 --in data.txt --outformat binary --out data."$k"-psssha1import.sig
      assert_success "Sign with rsa-pss-sha1"
    run openssl dgst -sha1 -binary -out data.sha1 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha1 -sigfile data."$k"-psssha1import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pss -i "$import_keyid" -A rsa-pss-sha256 --in data.txt --outformat binary --out data."$k"-psssha256import.sig
      assert_success "Sign with rsa-pss-sha256"
    run openssl dgst -sha256 -binary -out data.sha256 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha256 -sigfile data."$k"-psssha256import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pss -i "$import_keyid" -A rsa-pss-sha384 --in data.txt --outformat binary --out data."$k"-psssha384import.sig
      assert_success "Sign with rsa-pss-sha384"
    run openssl dgst -sha384 -binary -out data.sha384 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha384 -sigfile data."$k"-psssha384import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha384
      assert_success "Verify signature with openssl"
    run "${command_args[@]}" -p password -a sign-pss -i "$import_keyid" -A rsa-pss-sha512 --in data.txt --outformat binary --out data."$k"-psssha512import.sig
      assert_success "Sign with rsa-pss-sha512"
    run openssl dgst -sha512 -binary -out data.sha512 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha512 -sigfile data."$k"-psssha512import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha512
      assert_success "Verify signature with openssl"

    #Make self signed certificate
    if "${command_args[@]}" -p password -a sign-attestation-certificate -i "$keyid" --attestation-id 0 2>&1 > /dev/null;then #Some YubiHSMs does not have default attestation certificate
      run "${command_args[@]}" -p password -a sign-attestation-certificate -i "$keyid" --attestation-id 0 --out cert.pem
        assert_success "Sign attestation cert with default key"
      run openssl x509 -in cert.pem -out cert.der -outform DER
        assert_success "Convert cert format"
      run "${command_args[@]}" -p password -a put-opaque -i "$keyid" -l template_cert -A opaque-x509-certificate --in cert.der
        assert_success "Import attestation cert as template cert (same ID as generated key)"
      run "${command_args[@]}" -p password -a put-opaque -i "$import_keyid" -l template_cert -A opaque-x509-certificate --in cert.der
        assert_success "Import attestation cert as template cert (same ID as imported key)"
      run rm cert.der
        assert_success "Remove der cert"
    else
      run "${command_args[@]}" -p password -a put-opaque -i "$keyid" -l template_cert_gen -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem
        assert_success "Import attestation cert as template cert (same ID as generated key)"
      run "${command_args[@]}" -p password -a put-opaque -i "$import_keyid" -l template_cert_imp -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem
        assert_success "Import attestation cert as template cert (same ID as imported key)"
    fi
    run "${command_args[@]}" -p password -a sign-attestation-certificate -i "$keyid" --attestation-id="$keyid" --out selfsigned_cert.pem
      assert_success "Sign attestation with same key (aka. get selfsigned cert)"
    run "${command_args[@]}" -p password -a delete-object -i "$keyid" -t opaque
      assert_success "Delete template certificate"
    run "${command_args[@]}" -p password -a put-opaque -i "$keyid" -l java_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem
      assert_success "Import selfsigned with same key ID"
    run rm selfsigned_cert.pem
      assert_success "Remove selfsigned cert"

    #Sign attestation certificate
    run "${command_args[@]}" -p password -a sign-attestation-certificate -i "$keyid" --attestation-id="$import_keyid" --out selfsigned_cert.pem
      assert_success "Sign attestation cert with imported key"
    run rm selfsigned_cert.pem
      assert_success "Remove selfsigned cert"
    run "${command_args[@]}" -p password -a delete-object -i "$import_keyid" -t opaque
      assert_success "Delete template certificate"
    run "${command_args[@]}" -p password -a delete-object -i "$keyid" -t opaque
      assert_success "Delete template certificate"

    #Decryption with generated key and PKCS1v15
    run openssl rsautl -encrypt -inkey pubkey_rsa"$k".pem -pubin -in data.txt -out data.enc
      assert_success "Encrypt data with openssl"
    run "${command_args[@]}" -p password -a decrypt-pkcs1v15 -i "$keyid" --in data.enc --out data.dec
      assert_success "Decrypt data with yubihsm-shell"
    run cmp data.txt data.dec
      assert_success "Compare decrypted data with plain text data"
    run rm data.dec
      assert_success "Remove decrypted data"

    #Decryption with imported key and PKCS1v15
    run openssl rsautl -encrypt -inkey pubkey_rsa"$k".imported.pem -pubin -in data.txt -out data.enc
      assert_success "Encrypt data with openssl"
    run "${command_args[@]}" -p password -a decrypt-pkcs1v15 -i "$import_keyid" --in data.enc --out data.dec
      assert_success "Decrypt data with yubihsm-shell"
    run cmp data.txt data.dec
      assert_success "Compare decrypted data with plain text data"
    run rm data.dec
      assert_success "Remove decrypted data"
    
    #Make PKCS10 Certificate Signing Request
    run openssl req -new -key rsa$k-keypair.pem -subj /CN=test -out csr-ossl.pem
      assert_success "Generate CSR with OpenSSL"
    run "${command_args[@]}" -p password -a generate-csr -i "$import_keyid" -S /CN=test/ --out csr.pem
      assert_success "Generate CSR with yubihsm-shell"
    run openssl req -in csr.pem -verify
      assert_success "Verify CSR with openssl"
    run cmp csr-ossl.pem csr.pem
      assert_success "Compare CSR with OpenSSL generated CSR"
    run rm csr.pem csr-ossl.pem
      assert_success "Remove CSR"

    #Clean up
    run "${command_args[@]}" -p password -a delete-object -i "$keyid" -t asymmetric-key
      assert_success "Delete generated key"
    run "${command_args[@]}" -p password -a delete-object -i "$import_keyid" -t asymmetric-key
      assert_success "Delete imported key"
  done

  run openssl req -x509 -newkey rsa:4096 -out too_large_cert.pem -sha256 -days 3650 -nodes -subj '/C=01/ST=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/L=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/O=0123456789012345678901234567890123456789012345678901234567890123/OU=0123456789012345678901234567890123456789012345678901234567890123/CN=0123456789012345678901234567890123456789012345678901234567890123/CN=0123456789012345678901234567890123456789012345678901234567890123' > /dev/null 2>&1
    assert_success "Generate too large certificate with OpenSSL"
  
  run "${command_args[@]}" -p password -a put-opaque -i 100 -l too_large_cert -A opaque-x509-certificate --in too_large_cert.pem --informat PEM
    if [ "$status" -eq 0 ]; then
      assert_success "Import large certificate raw"
      echo "Imported x509 certificate raw" >&3
    elif [[ "$output" == *"Failed to store opaque object: Not enough space to store data"* ]]; then
      run "${command_args[@]}" -p password -a put-opaque -i 100 -l too_large_cert -A opaque-x509-certificate --with-compression --in too_large_cert.pem --informat PEM
        assert_success "Import compressed x509 certificate"
        echo "Imported compressed x509 Certificate" >&3
    else
      fail "Import of x509 certificate failed"
    fi

  run "${command_args[@]}" -p password -a get-opaque -i 100 --outformat=PEM --out too_large_cert_out.pem
    assert_success "Get too large certificate"
  run cmp too_large_cert.pem too_large_cert_out.pem
    assert_success "Compare imported and read certificate"

  run "${command_args[@]}" -p password -a delete-object -i 100 -t opaque
    assert_success "Delete too large certificate"
}

@test "HMAC Key tests" {
  [[ "$HMAC_KEY_TESTS" == "true" ]] || skip "skipping right now"
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")
  algorithms=("hmac-sha1" "hmac-sha256" "hmac-sha384" "hmac-sha512")

  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"
  sleep 3

  for algo in ${algorithms[@]}; do
    echo "$algo" >&3
    run "${command_args[@]}" -p password -a generate-hmac-key -i 0 -l hmackey -d 1,2,3 -c sign-hmac -A "$algo"
      assert_success "Generate "$algo" key"
    keyid=$(echo "$output" | tail -n 1 | awk '{print $4}')
    run "${command_args[@]}" -p password -a get-object-info -i "$keyid" -t hmac-key
    assert_success "get-object-info"
    assert_output --partial "id: "$keyid"" 
    assert_output --partial "type: hmac-key" 
    assert_output --partial "algorithm: "$algo"" 
    assert_output --partial "label: \"hmackey\""
    assert_output --partial "domains: 1:2:3"
    assert_output --partial "origin: generated"
    assert_output --partial "sign-hmac"
  done
}

@test "OTP AEAD Key tests" {
  [[ "$OTP_AEAD_TESTS" == "true" ]] || skip "skipping right now"
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")
  algorithms=("aes128" "aes192" "aes256")

  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"
  sleep 3

  for algo in ${algorithms[@]}; do
    echo "$algo" >&3
    run "${command_args[@]}" -p password -a generate-otp-aead-key -i 0 -l aeadkey -d 1,2,3 -c randomize-otp-aead -A "$algo"-yubico-otp --nonce 0x01020304
      assert_success "Generate Key"
    keyid=$(echo "$output" | tail -n 1 | awk '{print $5}')
    run "${command_args[@]}" -p password -a get-object-info -i "$keyid" -t otp-aead-key
      assert_success "Get object info"
      assert_output --partial "id: "$keyid"" 
      assert_output --partial "type: otp-aead-key" 
      assert_output --partial "algorithm: "$algo"-yubico-otp" 
      assert_output --partial "label: \"aeadkey\""
      assert_output --partial "domains: 1:2:3"
      assert_output --partial "origin: generated"
      assert_output --partial "capabilities: randomize-otp-aead"

    run "${command_args[@]}" -p password -a randomize-otp-aead -i "$keyid"
      assert_success "Randomize OTP AEAD"
    run "${command_args[@]}" -p password -a delete-object -i "$keyid" -t otp-aead-key
      assert_success "Delete key"
    
  done
}

@test "Template tests" {
  [[ "$TEMPLATE_TESTS" == "true" ]] || skip "skipping right now"
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")

  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"
  sleep 3

  run "${command_args[@]}" -p password -a put-template -i 20 -l "SSH_Template" -d 1 -A template-ssh --in ../template.dat
    assert_success "Import template"

  id=$(echo "$output" | grep "Stored Template object" | awk '{print $4}')
  run "${command_args[@]}" -p password -a get-object-info -i "$id" -t template
    assert_success "Get object info"
    assert_output --partial "id: "$id""
    assert_output --partial "type: template"
    assert_output --partial "algorithm: template-ssh"
    assert_output --partial "label: \"SSH_Template\""
    assert_output --partial "domains: 1"
    assert_output --partial "origin: imported"

  #This command doesn't work right now. 
  #run "${command_args[@]}" --authkey=0x0001 -p password -a sign-ssh-certificate -i 10 --template-id 20 -A rsa-pkcs1-sha256 --in ../req.dat --out ./id_rsa-cert.pub
    #assert_success "sign request"

  run "${command_args[@]}" -p password -a get-template -i "$id"
      assert_success "Get template"

  run "${command_args[@]}" -p password -a delete-object -i "$id" -t template
      assert_success "Delete template"
}

@test "Wrap Keys tests" {
  [[ "$WRAP_KEY_TESTS" == "true" ]] || skip "skipping right now"
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")
  algorithms=("aes128-ccm-wrap" "aes192-ccm-wrap" "aes256-ccm-wrap")
  eckey=100
  aeskey=200
  sequence=0
  RSA_KEYSIZE=("2048" "3072" "4096")
  seq_ec=6
  seq_aes=0
  aes_enabled=false

  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"
  sleep 3
  
  run "${command_args[@]}" -p password -a generate-asymmetric-key -i "$eckey" -l eckey -d 1 -c exportable-under-wrap,sign-ecdsa -A ecp224
    assert_success "Generate EC Key to wrap"
  run "${command_args[@]}" -p password -a get-object-info -i "$eckey" -t asymmetric-key
    assert_success "Get object info"
    assert_output --partial "sequence: "$sequence""
    sequence=$((sequence+1))
    assert_output --partial "origin: generated"
  
  for algo in ${algorithms[@]}; do
    echo "$algo" >&3
    length=24
    import_count=16
    if [ "$algo" == "aes192-ccm-wrap" ]; then
      length=32
      import_count=24
    elif [ "$algo" == "aes256-ccm-wrap" ]; then
      length=40
      import_count=32
    fi

    #Generate key
    run "${command_args[@]}" -p password -a generate-wrap-key -i 0 -l wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap -A "$algo"
      assert_success "Generate wrap key"
    keyid=$(echo "$output" | awk '/Generated Wrap key/ {print $4}')
    run "${command_args[@]}" -p password -a get-object-info -i "$keyid" -t wrap-key
      assert_success "Get object info"
      assert_output --partial "algorithm: "$algo""
      assert_output --partial "length: "$length""

    #Import key
    run "${command_args[@]}" -p password -a get-pseudo-random --count "$import_count"
      assert_success "Get random 16 bytes"
    wrapkey=$(echo "$output" | tail -n 1)
    run "${command_args[@]}" -p password -a put-wrap-key -i 0 -l imported_wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap --in="$wrapkey"
      assert_success "Import wrap key"

    import_keyid=$(echo "$output" | awk '/Stored Wrap key/ {print $4}') 
    run "${command_args[@]}" -p password -a get-object-info -i "$import_keyid" -t wrap-key
      assert_success "Get object info"
      assert_output --partial "algorithm: "$algo""
      assert_output --partial "length: "$length""
      assert_output --partial "origin: imported"

    #Wrap and unwrap with generated wrap key
    run "${command_args[@]}" -p password -a get-wrapped --wrap-id "$keyid" -i 100 -t asymmetric-key --out key.gen_wrapped
      assert_success "Wrap EC key"
    run "${command_args[@]}" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete EC key"
    run "${command_args[@]}" -p password -a put-wrapped --wrap-id "$keyid" --in key.gen_wrapped
      assert_success "Wrap EC key"
    run "${command_args[@]}" -p password -a get-object-info -i "$eckey" -t asymmetric-key
      assert_success "Get object info"
      assert_output --partial "sequence: "$sequence""
      sequence=$((sequence+1))
      assert_output --partial "origin: generated:imported_wrapped"
      assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
      assert_success "Perform signature with imported wrapped key"
  
    #Wrap and unwrap objects with imported wrap key
    run "${command_args[@]}" -p password -a get-wrapped --wrap-id "$import_keyid" -i 100 -t asymmetric-key --out key.imp_wrapped
      assert_success "Wrap EC key"
    run "${command_args[@]}" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete EC key"
    run "${command_args[@]}" -p password -a put-wrapped --wrap-id "$import_keyid" --in key.imp_wrapped
      assert_success "Wrap EC key"
    run "${command_args[@]}" -p password -a get-object-info -i "$eckey" -t asymmetric-key
      assert_success "Get object info"
      assert_output --partial "sequence: "$sequence""
      sequence=$((sequence+1))
      assert_output --partial "origin: generated:imported_wrapped"
      assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
      assert_success "Perform signature with imported wrapped key"
  
    #Clean up
    run "${command_args[@]}" -p password -a delete-object -i "$keyid" -t wrap-key
      assert_success "Delete generated wrap key"
    run "${command_args[@]}" -p password -a delete-object -i "$import_keyid" -t wrap-key
      assert_success "Delete imported wrap key"
    run rm key.gen_wrapped key.imp_wrapped
      assert_success "Deleted generated and imported wrap keys"
  done

  run "${command_args[@]}" -p password -a get-device-info
  assert_success "Get device info"

  if [[ "$output" != *"aes-kwp"* ]]; then
    run "${command_args[@]}" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete object"
    skip "Device does not support aes-kwp, skipping these tests."
  fi

  run "${command_args[@]}" -p password -a get-device-info
    assert_success "Get device info"
  if [[ "$output" == *"aes-cbc"* ]]; then
    aes_enabled=true
    run "${command_args[@]}" -p password -a generate-symmetric-key -i "$aeskey" -l aeskey -d 1 -c exportable-under-wrap,encrypt-cbc,decrypt-cbc -A aes128
      assert_success "Generate AES key to wrap"
    run "${command_args[@]}" -p password -a get-pseudo-random --count 16
      assert_success "Get random 16 bytes"
    iv=$(echo "$output" | tail -n 1)
    run "${command_args[@]}" -p password -a get-pseudo-random --count 32
      assert_success "Get random 32 bytes for encryption"
    data=$(echo "$output" | tail -n 1)
  fi

  for k in ${RSA_KEYSIZE[@]}; do
    echo "RSA"$k"" >&3
    if [[ "$k" != "2048" ]]; then
      echo "This may take a while..." >&3
    fi
    #Generate RSA wrap keys
    run "${command_args[@]}" -p password -a generate-wrap-key -i 0 -l wrapkey -c import-wrapped  --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc -A rsa"$k"
      assert_success "Generate RSA wrap key"
    keyid=$(echo "$output" | awk '/Generated Wrap key/ {print $4}')
    run "${command_args[@]}" -p password -a get-object-info -i "$keyid" -t wrap-key
      assert_success "Get object into"
      assert_output --partial "algorithm: rsa"$k""
      assert_output --partial "origin: generated"
    run "${command_args[@]}" -p password -a get-public-key -i "$keyid" -t wrap-key --out public_wrapkey.pem
      assert_success "Export rsa public wrap key"
    run "${command_args[@]}" -p password -a put-public-wrapkey -i "$keyid" -c export-wrapped --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc --in public_wrapkey.pem
      assert_success "Import RSA public wrap key"
    run rm public_wrapkey.pem
      assert_success "Delete wrapkey"
    
    #Wrap and unwrap EC object with generated wrap key
    run "${command_args[@]}" -p password -a get-rsa-wrapped --wrap-id "$keyid" -i "$eckey" -t asymmetric-key --out rsawrapped.object
      assert_success "Export wrapped EC object"
    run "${command_args[@]}" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete EC key"
    run "${command_args[@]}" -p password -a put-rsa-wrapped --wrap-id "$keyid" --in rsawrapped.object
      assert_success "Import wrapped EC object"
    run "${command_args[@]}" -p password -a get-object-info -i "$eckey" -t asymmetric-key
      assert_success "Get object info"
      seq_ec=$((seq_ec+1))
      assert_output --partial "sequence: "$seq_ec""
      assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
      assert_success "Perform signature with imported wrapped EC key"
    run rm rsawrapped.object
      assert_success "Removed RSA wrapped object"
    
    #Wrap and unwrap EC key material with generated RSA wrap key
    run "${command_args[@]}" -p password -a get-rsa-wrapped-key --wrap-id "$keyid" -i "$eckey" -t asymmetric-key --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --out rsawrapped.key
      assert_success "Export wrapped EC key material"
    run "${command_args[@]}" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete EC key"
    run "${command_args[@]}" -p password -a put-rsa-wrapped-key --wrap-id "$keyid" -i "$eckey" -t asymmetric-key -A ecp224 -c exportable-under-wrap,sign-ecdsa --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --in rsawrapped.key
      assert_success "Import wrapped EC key material"
    run "${command_args[@]}" -p password -a get-object-info -i "$eckey" -t asymmetric-key
      assert_success "Get object info"
      seq_ec=$((seq_ec+1))
      assert_output --partial "sequence: "$seq_ec""
      assert_output --partial "origin: imported:imported_wrapped"
      assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
      assert_success "Perform signature with imported wrapped EC key"
    run rm rsawrapped.key
      assert_success "Removed RSA wrapped key"
    
    if [[ "$aes_enabled" = true ]]; then
      #Wrap and unwrap AES object with generated RSA wrap key
      run "${command_args[@]}" -p password -a get-rsa-wrapped --wrap-id "$keyid" -i "$aeskey" -t symmetric-key --out rsawrapped.object
        assert_success "Export wrapped AES object"
      run "${command_args[@]}" -p password -a delete-object -i "$aeskey" -t symmetric-key
        assert_success "Delete AES key"
      run "${command_args[@]}" -p password -a put-rsa-wrapped --wrap-id "$keyid" --in rsawrapped.object
        assert_success "Import wrapped AES object"
      run "${command_args[@]}" -p password -a get-object-info -i "$aeskey" -t symmetric-key
        assert_success "Get object info"
        seq_aes=$((seq_aes+1))
        assert_output --partial "sequence: "$seq_aes""
        assert_output --partial "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap"
      run "${command_args[@]}" -p password -a encrypt-aescbc -i "$aeskey" --iv "$iv" --in "$data" --out data.enc
        assert_success "Perform encryption with imported wrapped AES key"
      run "${command_args[@]}" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        decrypted_data=$(echo "$output" | tail -n 1)
        assert_equal "$decrypted_data" "$data"
        assert_success "Perform decryption with imported wrapped AES key"

      run rm rsawrapped.object data.enc
        assert_success "Removed RSA wrapped object and encrypted data"
      
      #Wrap and unwrap AES key material with generated RSA wrap key
      run "${command_args[@]}" -p password -a get-rsa-wrapped-key --wrap-id "$keyid" -i "$aeskey" -t symmetric-key --oaep rsa-oaep-sha384 --mgf1 mgf1-sha1 --out rsawrapped.key
        assert_success "Export wrapped AES key material"
      run "${command_args[@]}" -p password -a delete-object -i "$aeskey" -t symmetric-key
        assert_success "Delete AES key"
      run "${command_args[@]}" -p password -a put-rsa-wrapped-key --wrap-id "$keyid" -i "$aeskey" -t symmetric-key -A aes128 -c exportable-under-wrap,decrypt-cbc,encrypt-cbc --oaep rsa-oaep-sha384 --mgf1 mgf1-sha1 --in rsawrapped.key
        assert_success "Import wrapped AES key material"
      run "${command_args[@]}" -p password -a get-object-info -i "$aeskey" -t symmetric-key
        assert_success "Get object info"
        seq_aes=$((seq_aes+1))
        assert_output --partial "sequence: "$seq_aes""
        assert_output --partial "origin: imported:imported_wrapped"
        assert_output --partial "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap"
      run "${command_args[@]}" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
        assert_success "Perform signature with imported wrapped EC key"
      run "${command_args[@]}" -p password -a encrypt-aescbc -i "$aeskey" --iv "$iv" --in "$data" --out data.enc
        assert_success "Perform encryption with imported wrapped AES key"
      run "${command_args[@]}" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Perform decryption with imported wrapped AES key"
      run "${command_args[@]}" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Decryption succeeded"
        last_line_of_output=$(echo "$output" | tail -n 1)
        assert_equal "$last_line_of_output" "$data"
      run rm rsawrapped.key data.enc
        assert_success "Removed RSA wrapped key and encrypted data"
    fi

    #Import RSA wrap keys
    run openssl genrsa -out keypair.pem "$k"
      assert_success "Generate RSA key with openssl"
    run openssl rsa -in keypair.pem -pubout -out key.pub
      assert_success "Extract public key from openssl generated keypair"
    run "${command_args[@]}" -p password -a put-rsa-wrapkey -i 0 -d 1 -c import-wrapped --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc --in keypair.pem
      assert_success "Import RSA wrap key"
    import_keyid=$(echo "$output" | awk '/Stored Wrap key/ {print $4}') 
    run "${command_args[@]}" -p password -a get-object-info -i "$import_keyid" -t wrap-key
      assert_success "Get object info"
      assert_output --partial "algorithm: rsa"$k""
      assert_output --partial "origin: imported"
    run "${command_args[@]}" -p password -a put-public-wrapkey -i "$import_keyid" -c export-wrapped --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc --in key.pub
      assert_success "Import RSA public wrap key"
    run rm keypair.pem key.pub
      assert_success "Remove keypairs"
    
    #Wrap and unwrap EC object with imported RSA wrap key
    run "${command_args[@]}" -p password -a get-rsa-wrapped --wrap-id "$import_keyid" -i "$eckey" -t asymmetric-key --out rsawrapped.object
      assert_success "Export wrapped EC object"
    run "${command_args[@]}" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete EC key"
    run "${command_args[@]}" -p password -a put-rsa-wrapped --wrap-id "$import_keyid" --in rsawrapped.object
      assert_success "Import wrapped EC objects"
    run "${command_args[@]}" -p password -a get-object-info -i "$eckey" -t asymmetric-key
      assert_success "Get object info"
      seq_ec=$((seq_ec+1))
      assert_output --partial "sequence: "$seq_ec""
      assert_output --partial "origin: imported:imported_wrapped"
      assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
      assert_success "Perform signature with imported wrapped EC key"
    run rm rsawrapped.object
      assert_success "Delete RSA wrapped object"
    
    #Wrap and unwrap EC key material with imported RSA wrap key
    run "${command_args[@]}" -p password -a get-rsa-wrapped-key --wrap-id "$import_keyid" -i "$eckey" -t asymmetric-key --oaep rsa-oaep-sha512 --mgf1 mgf1-sha512 --out rsawrapped.key
      assert_success "Export wrapped EC key material"
    run "${command_args[@]}" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete EC key"
    run "${command_args[@]}" -p password -a put-rsa-wrapped-key --wrap-id "$import_keyid" -i "$eckey" -t asymmetric-key -A ecp224 -c exportable-under-wrap,sign-ecdsa --oaep rsa-oaep-sha512 --mgf1 mgf1-sha512 --in rsawrapped.key
      assert_success "Import wrapped EC key material"
    run "${command_args[@]}" -p password -a get-object-info -i "$eckey" -t asymmetric-key
      assert_success "Get object info"
      seq_ec=$((seq_ec+1))
      assert_output --partial "sequence: "$seq_ec""
      assert_output --partial "origin: imported:imported_wrapped"
      assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
    run "${command_args[@]}" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
      assert_success "Perform signature with imported wrapped EC key"
    run rm rsawrapped.key
      assert_success "Removed RSA wrapped key"

    if [[ "$aes_enabled" = true ]]; then
      #Wrap and unwrap AES object with imported RSA wrap key
      run "${command_args[@]}" -p password -a get-rsa-wrapped --wrap-id "$import_keyid" -i "$aeskey" -t symmetric-key --out rsawrapped.object
        assert_success "Export wrapped AES object"
      run "${command_args[@]}" -p password -a delete-object -i "$aeskey" -t symmetric-key
        assert_success "Deleta AES key"
      run "${command_args[@]}" -p password -a put-rsa-wrapped --wrap-id "$import_keyid" --in rsawrapped.object
        assert_success "Import wrapped AES object"
      run "${command_args[@]}" -p password -a get-object-info -i "$aeskey" -t symmetric-key
        assert_success "Get object info"
        seq_aes=$((seq_aes+1))
        assert_output --partial "sequence: "$seq_aes""
        assert_output --partial "origin: imported:imported_wrapped"
        assert_output --partial "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap"
      run "${command_args[@]}" -p password -a encrypt-aescbc -i "$aeskey" --iv "$iv" --in "$data" --out data.enc
        assert_success "Perform encryption with imported wrapped AES key"
      run "${command_args[@]}" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Perform decryption with imported wrapped AES key"
      run "${command_args[@]}" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Decryption succeeded"
        last_line_of_output=$(echo "$output" | tail -n 1)
        assert_equal "$last_line_of_output" "$data"
      run rm rsawrapped.object data.enc
        assert_success "Removed RSA wrapped object and encrypted data"
      
      #Wrap and unwrap AES key material with imported RSA wrap key
      run "${command_args[@]}" -p password -a get-rsa-wrapped-key --wrap-id "$import_keyid" -i "$aeskey" -t symmetric-key --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --out rsawrapped.key
        assert_success "Export wrapped AES key material"
      run "${command_args[@]}" -p password -a delete-object -i "$aeskey" -t symmetric-key
        assert_success "Delete AES key"
      run "${command_args[@]}" -p password -a put-rsa-wrapped-key --wrap-id "$import_keyid" -i "$aeskey" -t symmetric-key -A aes128 -c exportable-under-wrap,decrypt-cbc,encrypt-cbc --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --in rsawrapped.key
        assert_success "Import wrapped AES key materiak"
      run "${command_args[@]}" -p password -a get-object-info -i "$aeskey" -t symmetric-key
        assert_success "Get object info"
        seq_aes=$((seq_aes+1))
        assert_output --partial "sequence: "$seq_aes""
        assert_output --partial "origin: imported:imported_wrapped"
        assert_output --partial "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap"
      run "${command_args[@]}" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
        assert_success "Perform encryption with imported wrapped EC key"
      run "${command_args[@]}" -p password -a encrypt-aescbc -i "$aeskey" --iv "$iv" --in "$data" --out data.enc
        assert_success "Perform encryption with imported wrapped AES key"
      run "${command_args[@]}" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Perform decryption with imported wrapped AES key"
      run "${command_args[@]}" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Decryption succeeded"
        last_line_of_output=$(echo "$output" | tail -n 1)
        assert_equal "$last_line_of_output" "$data" 
      run rm rsawrapped.key data.enc
        assert_success "Removed RSA wrapped key and encrypted data"

    fi
    #Clean up
    run "${command_args[@]}" -p password -a delete-object -i "$keyid" -t wrap-key
      assert_success "Delete generated RSA wrap key"
    run "${command_args[@]}" -p password -a delete-object -i "$keyid" -t public-wrap-key
      assert_success "Delete generated RSA public wrap key"
    run "${command_args[@]}" -p password -a delete-object -i "$import_keyid" -t wrap-key
      assert_success "Delete imported RSA wrap key"
    run "${command_args[@]}" -p password -a delete-object -i "$import_keyid" -t public-wrap-key
      assert_success "Delete imported RSA public wrap key"
  done
}

@test "List Objects" {
  [[ "$LIST_TESTS" == "true" ]] || skip "skipping right now"
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")

  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"
  sleep 3

  run "${command_args[@]}" -p password -a generate-asymmetric-key -i 100 -l ecKey -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp224
      assert_success "Generate EC key for testing"

  run "${command_args[@]}" -p password -a list-objects -A any -t any -i 100
      assert_success "List objects by ID"
      assert_output --partial "Found 1 object(s)"

  run "${command_args[@]}" -p password -a list-objects -A any -t asymmetric-key
      assert_success "List objects by type"
      assert_output --partial "Found 1 object(s)"

  run "${command_args[@]}" -p password -a list-objects -A any -t any -d 5,8,13
      assert_success "List objects by domain"
      assert_output --partial "Found 2 object(s)"

  run "${command_args[@]}" -p password -a list-objects -A any -t any -c sign-ecdsa,derive-ecdh,sign-attestation-certificate
      assert_success "List objects by capabilities"
      assert_output --partial "Found 2 object(s)"

  run "${command_args[@]}" -p password -a list-objects -A ecp224 -t any
      assert_success "List objects by algorithm"
      assert_output --partial "Found 1 object(s)"

  run "${command_args[@]}" -p password -a list-objects -A any -t any -l ecKey
      assert_success "List objects by label"
      assert_output --partial "Found 1 object(s)"

  run "${command_args[@]}" -p password -a delete-object -i 100 -t asymmetric-key
      assert_success "Delete key"
}

@test "Label Size" {
  [[ "$LABEL_TESTS" == "true" ]] || skip "skipping right now"
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")

  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"
  sleep 3

  run "${command_args[@]}" -p password -a generate-asymmetric-key -i 300 -d 5,8,13 -c sign-ecdsa -A ecp224
    assert_success "Create key with no label"
    
  run "${command_args[@]}" -p password -a get-object-info -i 300 -t asymmetric-key
    assert_success "Get info for key with no label"
    assert_output --partial "label: \"\""

    # --- Test with 39-character label ---
  run "${command_args[@]}" -p password -a generate-asymmetric-key -i 200 -l abcdefghijklmnopqrstuvwxyz0123456789abc -d 5,8,13 -c sign-ecdsa -A ecp224
    assert_success "Create object with 39-character label"

  run "${command_args[@]}" -p password -a get-object-info -i 200 -t asymmetric-key
    assert_success "Get info for 39-character label"
    assert_output --partial "label: \"abcdefghijklmnopqrstuvwxyz0123456789abc\""

  run "${command_args[@]}" -p password -a list-objects -A any -t any -l abcdefghijklmnopqrstuvwxyz0123456789abc
    assert_success "List objects with 39-character label"
    assert_output --partial "Found 1 object(s)"

    # --- Test with 40-character label ---
  run "${command_args[@]}" -p password -a generate-asymmetric-key -i 100 -l abcdefghijklmnopqrstuvwxyz0123456789abcd -d 5,8,13 -c sign-ecdsa -A ecp224
    assert_success "Create object with 40-character label"

  run "${command_args[@]}" -p password -a list-objects -A any -t any -l abcdefghijklmnopqrstuvwxyz0123456789abcd
    assert_success "List objects with 40-character label"
    assert_output --partial "Found 1 object(s)"

    # --- Test that 41-character label FAILS ---
  run "${command_args[@]}" -p password -a generate-asymmetric-key -i 400 -l "abcdefghijklmnopqrstuvwxyz0123456789abcde" -d "5,8,13" -c "sign-ecdsa" -A "ecp224"
    assert_failure
    assert_output --partial "Invalid argument to a function"

    # --- Test listing a non-existent label ---
  run "${command_args[@]}" -p password -a list-objects -A any -t any -l doesnotexist
    assert_success "List objects by non-existent label"
    assert_output --partial "Found 0 object(s)"

    # --- Clean up created objects ---
  run "${command_args[@]}" -p password -a delete-object -i 100 -t asymmetric-key
    assert_success "Clean up key 100"
    
  run "${command_args[@]}" -p password -a delete-object -i 200 -t asymmetric-key
    assert_success "Clean up key 200"

  run "${command_args[@]}" -p password -a delete-object -i 300 -t asymmetric-key
    assert_success "Clean up key 300"
}

@test "Authentication" {
  [[ "$AUTHENTICATION_TESTS" == "true" ]] || skip "skipping right now"
  command_args=("$BIN" "$c_var" "$SPECIFIED_CONNECTOR")

  run "${command_args[@]}" -p password -a reset
    assert_success "HSM was reset"
  sleep 3

  run "${command_args[@]}" -p password -a put-authentication-key -i 0 -l authkey -d 1,2,3 -c all --delegated all --new-password foo123
      assert_success "Create new authentication key"

  keyid=$(echo "$output" | tail -1 | awk '{print $4}')
  run "${command_args[@]}" --authkey "$keyid" -p foo123 -a get-object-info -i 1 -t authentication-key
      assert_success "Authenticate with new authentication key"

  run "${command_args[@]}" -p password -a delete-object -i "$keyid" -t authentication-key
      assert_success "Delete authentication key"
}