load 'test_helper/bats-support/load'
load 'test_helper/bats-assert/load'

setup_file() {
  
  echo "--- Configuration via Environment Variables ---" >&3
  echo "YUBIHSM_PATH: path to the yubihsm-shell command line tool - using default connector." >&3
  echo "SPECIFIED_CONNECTOR:      path to the yubihsm-shell command line tool - using specified connector" >&3
  echo "<test>=false: Choose to skip test" >&3
  echo " ED_KEY_TESTS EC_KEY_TESTS RSA_KEY_TESTS HMAC_KEY_TESTS OTP_AEAD_TESTS TEMPLATE_TESTS WRAP_KEYS_TESTS LIST_TESTS LABEL_TESTS AUTHENTICATION_TESTS" >&3
  echo "-----------------------------------------------" >&3
  echo "These tests will reset your HSM" >&3
  echo "Press Enter to continue or Ctrl-C + enter to abort" >&3
  read -p "" 


  export ED_KEY_TESTS=${ED_KEY_TESTS:-"true"}
  export EC_KEY_TESTS=${EC_KEY_TESTS:-"true"}
  export RSA_KEY_TESTS=${RSA_KEY_TESTS:-"true"}
  export HMAC_KEY_TESTS=${HMAC_KEY_TESTS:-"true"}
  export OTP_AEAD_TESTS=${OTP_AEAD_TESTS:-"true"}
  export TEMPLATE_TESTS=${TEMPLATE_TESTS:-"true"}
  export WRAP_KEYS_TESTS=${WRAP_KEYS_TESTS:-"true"}
  export LIST_TESTS=${LIST_TESTS:-"true"}
  export LABEL_TESTS=${LABEL_TESTS:-"true"}
  export AUTHENTICATION_TESTS=${AUTHENTICATION_TESTS:-"true"}



  local default_bin_path="yubihsm-shell"
  export c_var=""
  #local specified_connector="yhusb://"
  local winpath
  winpath=$(uname -o) 

  if [[ "$winpath" == "Msys" ]]; then
    default_bin_path=";C:/Program Files/Yubico/YubiHSM Shell/bin"
    export MSYS2_ARG_CONV_EXCL=* # To prevent path conversion by MSYS2

  elif [[ "$winpath" == "GNU/Linux" || "$winpath" == "Darwin" ]]; then
    default_bin_path="/usr/local/bin/yubihsm-shell"
  fi

  if [ -n "$SPECIFIED_CONNECTOR" ]; then # Specified connector exists
    echo "Specified connector exists" >&3
    c_var="-C"
  fi
  export BIN=${YUBIHSM_PATH:-$default_bin_path}
  export SPECIFIED_CONNECTOR=${SPECIFIED_CONNECTOR:-""}
  

}

@test "Test basic functions, Reset HSM and get Pseudo-Random" {
    #skip "skipping right now as it works"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" --version
    assert_success "Version works"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" --help
    assert_success "Help works"
  
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -a get-device-info  
    assert_success "Get device info"
    assert_output --partial "Serial number:"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a reset
    assert_success "HSM was reset"
    sleep 3

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a blink
    assert_success "Blink works"
  
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a blink --duration=5
    assert_success "Blink with duration works"

  run bash -c ""$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-pseudo-random | wc -c" # Not sure why this works with "bash -c "
    assert_success "Get Pseudo-Random works" 
    assert_output --partial "513"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-pseudo-random --out=random.txt
    assert_success "Get Pseudo-Random to file works"

  length=$(cat random.txt | wc -c)
  if [ "$length" -ne 512 ]; then
    echo "Expected 512 but was $length characters. Without specifying byte count, 256 bytes (=512 characters) pseudo random number should have been produced." >&3
    exit 1
  fi
  rm random.txt

  run bash -c ""$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-pseudo-random --count=10 |wc -c" # Not sure why this works with "bash -c "
    assert_success "Get pseudo-random with --count=10"
    assert_output --partial "21"


  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-pseudo-random --count=10 --out=random.txt
    assert_success "Get pseudo-random with --count=10"
    length=$(cat random.txt | wc -c)
    if [ "$length" -ne 20 ]; then
      echo "Expected 20 but was $length characters." >&3
      exit 1
    fi
    rm random.txt
}

@test "ED Key tests" {
  [[ "$ED_KEY_TESTS" == "true" ]] || skip "skipping right now"

  if [ -e yubihsm-shell_test_dir ]; then
    rm -rf yubihsm-shell_test_dir
  fi
  mkdir yubihsm-shell_test_dir; cd yubihsm-shell_test_dir
  echo test signing data > data.txt
  #Generate
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-asymmetric-key -i 100 -l \"edKey\" -d 1,2,3 -c sign-eddsa -A ed25519
    assert_success "Generate key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i 100 -t asymmetric-key
    assert_success "get-object-info"
    assert_output --partial "id: 0x0064" 
    assert_output --partial "type: asymmetric-key" 
    assert_output --partial "algorithm: ed25519" 
    assert_output --partial 'label: ""edKey""' 
    assert_output --partial "domains: 1:2:3"
    assert_output --partial "origin: generated"
    assert_output --partial "capabilities: sign-eddsa"

  #Get public key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-public-key -i 100
    assert_success "Get public key"
  "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-public-key -i 100 > edkey1.pub 2>/dev/null
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-public-key -i 100 --out edkey2.pub
    assert_success "Get public key to file"
  run cmp edkey1.pub edkey2.pub
    assert_success "Match public key in stdout and file"

  #Signing
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt
    assert_success "Sign to stdout"
  "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt > data.ed1.sig 2>/dev/null
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-eddsa -i 100 -A ed25519 --in data.txt --out data.ed2.sig
    assert_success "Sign to file"
  local content1
  content1=$(tr -d '[:space:]' < data.ed1.sig)
  local content2
  content2=$(tr -d '[:space:]' < data.ed2.sig)
  assert_equal "$content1" "$content2"

  #Generating CSR
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-csr -i 100 -S /CN=test/ --out csr.pem
    assert_success "Generate CSR with yubihsm-shell"
  run openssl req -in csr.pem -verify
    assert_success "Verify CSR with openssl"
  
  #Delete
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i 100 -t asymmetric-key
    assert_success "Delete key"
}

@test "EC Key tests" {
  [[ "$EC_KEY_TESTS" == "true" ]] || skip "skipping right now"
  

    EC_ALGOS=("ecp224" "ecp256" "ecp384" "ecp521" "eck256")
    EC_CURVES=("secp224r1" "secp256r1" "secp384r1" "secp521r1" "secp256k1")
    if grep -q 'Fedora' /etc/os-release; then
      EC_ALGOS+=" ecbp256 ecbp384 ecbp512"
      EC_CURVES+=" brainpoolP256r1 brainpoolP384r1 brainpoolP512r1"
    fi
    genkey=100
    import_key=200

    if [ -e yubihsm-shell_test_dir ]; then
    rm -rf yubihsm-shell_test_dir
    fi
    mkdir yubihsm-shell_test_dir; cd yubihsm-shell_test_dir
    echo test signing data > data.txt

  if [ -z ${DOCKER_IMAGE} ] || [ ${DOCKER_IMAGE} != "centos:7" ]; then
      # This DOCKER_IMAGE environment variable is set in the build_and_test.yml github workflow.
        for i in "${!EC_ALGOS[@]}"; do
        algo=${EC_ALGOS[i]}
        curve=${EC_CURVES[i]}
        echo "Testing $algo with curve $curve" >&3

        #Generate Key
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-asymmetric-key -i "$genkey" -l \"ecKey\" -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A "$algo"
          assert_success "Generate key"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$genkey" -t asymmetric-key
          assert_success "get-object-info"
          assert_output --partial "id: 0x0064" 
          assert_output --partial "type: asymmetric-key" 
          assert_output --partial "algorithm: "$algo"" 
          assert_output --partial 'label: ""ecKey""' 
          assert_output --partial "domains: 5:8:13"
          assert_output --partial "origin: generated"
          assert_output --partial "capabilities: derive-ecdh:sign-attestation-certificate:sign-ecdsa"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-public-key -i "$genkey" --outformat=PEM --out "$algo"-gen.pubkey
          assert_success "Get public key"
        
        #Import Key
        run openssl ecparam -genkey -name "$curve" -noout -out "$curve"-keypair.pem
          assert_success "Generate key with openssl"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-asymmetric-key -i "$import_key" -l "ecKeyImport" -d "2,6,7" -c "sign-ecdsa,sign-attestation-certificate" --in="$curve"-keypair.pem
          assert_success "Import $algo key"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$import_key" -t asymmetric-key
          assert_success "get-object-info"
          assert_output --partial "id: 0x00c8" 
          assert_output --partial "type: asymmetric-key" 
          assert_output --partial "algorithm: "$algo"" 
          assert_output --partial 'label: "ecKeyImport"' 
          assert_output --partial "domains: 2:6:7"
          assert_output --partial "origin: imported"
          assert_output --partial "capabilities: sign-attestation-certificate:sign-ecdsa"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-public-key -i "$import_key" --outformat=PEM --out "$algo"-import.pubkey
          assert_success "Get public key"
        
        #Signing
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$genkey" -A ecdsa-sha1 --in data.txt --outformat=PEM --out data."$algo"-sha1gen.sig
          assert_success "Sign with generated key and ecdsa-sha1"
        run openssl dgst -sha1 -verify "$algo"-gen.pubkey -signature data."$algo"-sha1gen.sig data.txt
          assert_success "Verify signature with openssl"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$genkey" -A ecdsa-sha256 --in data.txt --outformat=PEM --out data."$algo"-sha256gen.sig
          assert_success "Sign with generated key and ecdsa-sha256"
        run openssl dgst -sha256 -verify "$algo"-gen.pubkey -signature data."$algo"-sha256gen.sig data.txt
          assert_success "Verify signature with openssl"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$genkey" -A ecdsa-sha384 --in data.txt --outformat=PEM --out data."$algo"-sha384gen.sig
          assert_success "Sign with generated key and ecdsa-sha384"
        run openssl dgst -sha384 -verify "$algo"-gen.pubkey -signature data."$algo"-sha384gen.sig data.txt
          assert_success "Verify signature with openssl"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$genkey" -A ecdsa-sha512 --in data.txt --outformat=PEM --out data."$algo"-sha512gen.sig
          assert_success "Sign with generated key and ecdsa-sha512"
        run openssl dgst -sha512 -verify "$algo"-gen.pubkey -signature data."$algo"-sha512gen.sig data.txt
          assert_success "Verify signature with openssl"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$import_key" -A ecdsa-sha1 --in data.txt --outformat=PEM --out data."$algo"-sha1import.sig
          assert_success "Sign with imported key and ecdsa-sha1"
        run openssl dgst -sha1 -verify "$algo"-import.pubkey -signature data."$algo"-sha1import.sig data.txt
          assert_success "Verify signature with openssl"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$import_key" -A ecdsa-sha256 --in data.txt --outformat=PEM --out data."$algo"-sha256import.sig
          assert_success "Sign with imported key and ecdsa-sha256"
        run openssl dgst -sha256 -verify "$algo"-import.pubkey -signature data."$algo"-sha256import.sig data.txt
          assert_success "Verify signature with openssl"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$import_key" -A ecdsa-sha384 --in data.txt --outformat=PEM --out data."$algo"-sha384import.sig
          assert_success "Sign with imported key and ecdsa-sha384"
        run openssl dgst -sha384 -verify "$algo"-import.pubkey -signature data."$algo"-sha384import.sig data.txt
          assert_success "Verify signature with openssl"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$import_key" -A ecdsa-sha512 --in data.txt --outformat=PEM --out data."$algo"-sha512import.sig
          assert_success "Sign with imported key and ecdsa-sha512"
        run openssl dgst -sha512 -verify "$algo"-import.pubkey -signature data."$algo"-sha512import.sig data.txt
          assert_success "Verify signature with openssl"
        
        #Get attestation certificate and selfsigned certificate
        if "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-attestation-certificate -i "$genkey" --attestation-id 0 2>&1 > /dev/null;then # Some YubiHSMs does not have default attestation certificate
          run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-attestation-certificate -i "$genkey" --attestation-id 0 --out cert.pem
            assert_success "Sign attestation cert with default key"
          run openssl x509 -in cert.pem -out cert.der -outform DER
            assert_success "Convert cert format"
          run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i "$genkey" -l template_cert -A opaque-x509-certificate --in cert.der
            assert_success "Import attestation cert as template cert (same ID as generated key)"
          run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i "$import_key" -l template_cert -A opaque-x509-certificate --in cert.der
            assert_success "Import attestation cert as template cert (same ID as imported key)"
          run rm cert.der
            assert_success "Remove der cert"
        else
          run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i "$genkey" -l template_cert_gen -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem
            assert_success "Import attestation cert as template cert (same ID as generated key)"
          run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i "$import_key" -l template_cert_imp -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem
            assert_success "Import attestation cert as template cert (same ID as imported key)"
        fi

        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-attestation-certificate -i "$genkey" --attestation-id="$genkey" --out selfsigned_cert.pem
          assert_success "Get selfsigned certificate"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$genkey" -t opaque
          assert_success "Delete template certificate"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i "$genkey" -l java_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem
          assert_success "Import selfsigned with same key ID"
        run rm selfsigned_cert.pem
          assert_success "Remove selfsigned cert"

        #Sign attestation certificate
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-attestation-certificate -i "$genkey" --attestation-id="$import_key" --out selfsigned_cert.pem
          assert_success "Sign attestation cert with imported key"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$genkey" -t opaque
          assert_success "Delete template certificate"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$import_key" -t opaque
          assert_success "Delete template certificate"
        run rm selfsigned_cert.pem
          assert_success "Remove selfsigned cert"

        #Derive ECDH
        run openssl ec -in "$curve"-keypair.pem -pubout -out "$curve"-pubkey.pem
          assert_success "Get imported key public key with OpenSSL"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a derive-ecdh -i "$genkey" --in "$curve"-pubkey.pem --outformat binary --out "$algo"-ecdh-shell.key
          assert_success "Derive ECDH key with yubihsm-shell"
        run openssl pkeyutl -derive -inkey "$curve"-keypair.pem -peerkey "$algo"-gen.pubkey -out "$algo"-ecdh-openssl.key
          assert_success "Derive ECDH key with OpenSSL"
        run cmp "$algo"-ecdh-shell.key "$algo"-ecdh-openssl.key
          assert_success "Compare derived keys"

        #make PKCS10 certificate signing request
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-csr -i "$genkey" -S /CN=test/ --out csr.pem
          assert_success "Generate CSR with yubihsm-shell"
        run openssl req -in csr.pem -verify
          assert_success "Verify CSR with openssl"
        run rm csr.pem
          assert_success "Remove CSR"

        #Clean up
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$genkey" -t asymmetric-key
          assert_success "Delete generated key"
        run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$import_key" -t asymmetric-key
          assert_success "Delete imported key"
    done
  else
      skip "Skipping EC key tests on centos:7 as it does not have the required openssl version"
  fi
}

@test "RSA Key tests" {
  [[ "$RSA_KEY_TESTS" == "true" ]] || skip "skipping right now"

  RSA_KEYSIZE=("2048" "3072" "4096")

  if [ -e yubihsm-shell_test_dir ]; then
    rm -rf yubihsm-shell_test_dir
  fi
  mkdir yubihsm-shell_test_dir; cd yubihsm-shell_test_dir
  echo test signing and decryption data > data.txt

  for k in ${RSA_KEYSIZE[@]}; do
    echo "Testing RSA with key size "$k"" >&3
    if [ "$k" -ne "2048" ]; then
    echo "This may take a while..." >&3
    fi
    #Generate Key
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-asymmetric-key -i 0 -l rsaKey -d 1 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate -A rsa"$k"
      assert_success "Generate RSA "$k" key"

    keyid=$(echo "$output" | tail -1 | awk '{print $4}')
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t asymmetric-key
      assert_success "get-object-info"
      assert_output --partial "id: "$keyid"" 
      assert_output --partial "type: asymmetric-key" 
      assert_output --partial "algorithm: rsa"$k"" 
      assert_output --partial "label: \"rsaKey\""
      assert_output --partial "domains: 1"
      assert_output --partial "origin: generated"
      assert_output --partial "decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-public-key -i "$keyid" --outformat=PEM --out pubkey_rsa"$k".pem
      assert_success "Get public key"

    #Import key
    run openssl genrsa -out rsa"$k"-keypair.pem "$k"
      assert_success "Generate key with OpenSSL"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-asymmetric-key -i 0 -l rsaKeyImport -d 2 -c sign-pkcs,sign-pss,decrypt-pkcs,decrypt-oaep,sign-attestation-certificate --in=rsa"$k"-keypair.pem
      assert_success "Import key"

    import_keyid=$(echo "$output" | tail -1 | awk '{print $4}')
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$import_keyid" -t asymmetric-key
      assert_success "get-object-info"
      assert_output --partial "id: "$import_keyid"" 
      assert_output --partial "type: asymmetric-key" 
      assert_output --partial "algorithm: rsa"$k"" 
      assert_output --partial "label: \"rsaKeyImport\""
      assert_output --partial "domains: 2"
      assert_output --partial "origin: imported"
      assert_output --partial "decrypt-oaep:decrypt-pkcs:sign-attestation-certificate:sign-pkcs:sign-pss"
    
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-public-key -i "$import_keyid" --outformat=PEM --out pubkey_rsa"$k".imported.pem
      assert_success "Get public key"

    #Signing with generated key
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pkcs1v15 -i "$keyid" -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data."$k"-pkcs1sha1gen.sig
      assert_success "Sign with rsa-pkcs1-sha1"
    run openssl dgst -sha1 -verify pubkey_rsa"$k".pem -signature data."$k"-pkcs1sha1gen.sig data.txt
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pkcs1v15 -i "$keyid" -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data."$k"-pkcs1sha256gen.sig
      assert_success "Sign with rsa-pkcs1-sha256"
    run openssl dgst -sha256 -verify pubkey_rsa"$k".pem -signature data."$k"-pkcs1sha256gen.sig data.txt
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pkcs1v15 -i "$keyid" -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data."$k"-pkcs1sha384gen.sig
      assert_success "Sign with rsa-pkcs1-sha384"
    run openssl dgst -sha384 -verify pubkey_rsa"$k".pem -signature data."$k"-pkcs1sha384gen.sig data.txt
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pkcs1v15 -i "$keyid" -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data."$k"-pkcs1sha512gen.sig
      assert_success "Sign with rsa-pkcs1-sha512"
    run openssl dgst -sha512 -verify pubkey_rsa"$k".pem -signature data."$k"-pkcs1sha512gen.sig data.txt
      assert_success "Verify signature with openssl"


    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pss -i "$keyid" -A rsa-pss-sha1 --in data.txt --outformat binary --out data."$k"-psssha1gen.sig
      assert_success "Sign with rsa-pss-sha1"
    run openssl dgst -sha1 -binary -out data.sha1 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha1 -sigfile data."$k"-psssha1gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pss -i "$keyid" -A rsa-pss-sha256 --in data.txt --outformat binary --out data."$k"-psssha256gen.sig
      assert_success "Sign with rsa-pss-sha256"
    run openssl dgst -sha256 -binary -out data.sha256 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha256 -sigfile data."$k"-psssha256gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pss -i "$keyid" -A rsa-pss-sha384 --in data.txt --outformat binary --out data."$k"-psssha384gen.sig
      assert_success "Sign with rsa-pss-sha384"
    run openssl dgst -sha384 -binary -out data.sha384 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha384 -sigfile data."$k"-psssha384gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha384
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pss -i "$keyid" -A rsa-pss-sha512 --in data.txt --outformat binary --out data."$k"-psssha512gen.sig
      assert_success "Sign with rsa-pss-sha512"
    run openssl dgst -sha512 -binary -out data.sha512 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha512 -sigfile data."$k"-psssha512gen.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha512
      assert_success "Verify signature with openssl"
    
    #Signing with imported key
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pkcs1v15 -i "$import_keyid" -A rsa-pkcs1-sha1 --in data.txt --outformat binary --out data."$k"-pkcs1sha1import.sig
      assert_success "Sign with rsa-pkcs1-sha1"
    run openssl dgst -sha1 -verify pubkey_rsa"$k".imported.pem -signature data."$k"-pkcs1sha1import.sig data.txt
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pkcs1v15 -i "$import_keyid" -A rsa-pkcs1-sha256 --in data.txt --outformat binary --out data."$k"-pkcs1sha256import.sig
      assert_success "Sign with rsa-pkcs1-sha256"
    run openssl dgst -sha256 -verify pubkey_rsa"$k".imported.pem -signature data."$k"-pkcs1sha256import.sig data.txt
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pkcs1v15 -i "$import_keyid" -A rsa-pkcs1-sha384 --in data.txt --outformat binary --out data."$k"-pkcs1sha384import.sig
      assert_success "Sign with rsa-pkcs1-sha384"
    run openssl dgst -sha384 -verify pubkey_rsa"$k".imported.pem -signature data."$k"-pkcs1sha384import.sig data.txt
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pkcs1v15 -i "$import_keyid" -A rsa-pkcs1-sha512 --in data.txt --outformat binary --out data."$k"-pkcs1sha512import.sig
      assert_success "Sign with rsa-pkcs1-sha512"
    run openssl dgst -sha512 -verify pubkey_rsa"$k".imported.pem -signature data."$k"-pkcs1sha512import.sig data.txt
      assert_success "Verify signature with openssl"

    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pss -i "$import_keyid" -A rsa-pss-sha1 --in data.txt --outformat binary --out data."$k"-psssha1import.sig
      assert_success "Sign with rsa-pss-sha1"
    run openssl dgst -sha1 -binary -out data.sha1 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha1 -sigfile data."$k"-psssha1import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pss -i "$import_keyid" -A rsa-pss-sha256 --in data.txt --outformat binary --out data."$k"-psssha256import.sig
      assert_success "Sign with rsa-pss-sha256"
    run openssl dgst -sha256 -binary -out data.sha256 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha256 -sigfile data."$k"-psssha256import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pss -i "$import_keyid" -A rsa-pss-sha384 --in data.txt --outformat binary --out data."$k"-psssha384import.sig
      assert_success "Sign with rsa-pss-sha384"
    run openssl dgst -sha384 -binary -out data.sha384 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha384 -sigfile data."$k"-psssha384import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha384
      assert_success "Verify signature with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-pss -i "$import_keyid" -A rsa-pss-sha512 --in data.txt --outformat binary --out data."$k"-psssha512import.sig
      assert_success "Sign with rsa-pss-sha512"
    run openssl dgst -sha512 -binary -out data.sha512 data.txt
      assert_success "Hash data with openssl"
    run openssl pkeyutl -verify -in data.sha512 -sigfile data."$k"-psssha512import.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_rsa"$k".imported.pem -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha512
      assert_success "Verify signature with openssl"

    #Make self signed certificate
    if "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-attestation-certificate -i "$keyid" --attestation-id 0 2>&1 > /dev/null;then #Some YubiHSMs does not have default attestation certificate
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-attestation-certificate -i "$keyid" --attestation-id 0 --out cert.pem
        assert_success "Sign attestation cert with default key"
      run openssl x509 -in cert.pem -out cert.der -outform DER
        assert_success "Convert cert format"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i "$keyid" -l template_cert -A opaque-x509-certificate --in cert.der
        assert_success "Import attestation cert as template cert (same ID as generated key)"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i "$import_keyid" -l template_cert -A opaque-x509-certificate --in cert.der
        assert_success "Import attestation cert as template cert (same ID as imported key)"
      run rm cert.der
        assert_success "Remove der cert"
    else
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i "$keyid" -l template_cert_gen -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem
        assert_success "Import attestation cert as template cert (same ID as generated key)"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i "$import_keyid" -l template_cert_imp -A opaque-x509-certificate --informat=PEM --in ../test_x509template.pem
        assert_success "Import attestation cert as template cert (same ID as imported key)"
    fi
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-attestation-certificate -i "$keyid" --attestation-id="$keyid" --out selfsigned_cert.pem
      assert_success "Sign attestation with same key (aka. get selfsigned cert)"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t opaque
      assert_success "Delete template certificate"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i "$keyid" -l java_cert -A opaque-x509-certificate --informat=PEM --in selfsigned_cert.pem
      assert_success "Import selfsigned with same key ID"
    run rm selfsigned_cert.pem
      assert_success "Remove selfsigned cert"

    #Sign attestation certificate
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-attestation-certificate -i "$keyid" --attestation-id="$import_keyid" --out selfsigned_cert.pem
      assert_success "Sign attestation cert with imported key"
    run rm selfsigned_cert.pem
      assert_success "Remove selfsigned cert"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$import_keyid" -t opaque
      assert_success "Delete template certificate"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t opaque
      assert_success "Delete template certificate"

    #Decryption with generated key and PKCS1v15
    run openssl rsautl -encrypt -inkey pubkey_rsa"$k".pem -pubin -in data.txt -out data.enc
      assert_success "Encrypt data with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a decrypt-pkcs1v15 -i "$keyid" --in data.enc --out data.dec
      assert_success "Decrypt data with yubihsm-shell"
    run cmp data.txt data.dec
      assert_success "Compare decrypted data with plain text data"
    run rm data.dec
      assert_success "Remove decrypted data"

    #Decryption with imported key and PKCS1v15
    run openssl rsautl -encrypt -inkey pubkey_rsa"$k".imported.pem -pubin -in data.txt -out data.enc
      assert_success "Encrypt data with openssl"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a decrypt-pkcs1v15 -i "$import_keyid" --in data.enc --out data.dec
      assert_success "Decrypt data with yubihsm-shell"
    run cmp data.txt data.dec
      assert_success "Compare decrypted data with plain text data"
    run rm data.dec
      assert_success "Remove decrypted data"
    
    #Make PKCS10 Certificate Signing Request
    run openssl req -new -key rsa$k-keypair.pem -subj /CN=test -out csr-ossl.pem
      assert_success "Generate CSR with OpenSSL"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-csr -i "$import_keyid" -S /CN=test/ --out csr.pem
      assert_success "Generate CSR with yubihsm-shell"
    run openssl req -in csr.pem -verify
      assert_success "Verify CSR with openssl"
    run cmp csr-ossl.pem csr.pem
      assert_success "Compare CSR with OpenSSL generated CSR"
    run rm csr.pem csr-ossl.pem
      assert_success "Remove CSR"

    #Clean up
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t asymmetric-key
      assert_success "Delete generated key"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$import_keyid" -t asymmetric-key
      assert_success "Delete imported key"
  done

  echo "Compress x509 Certificate" >&3

  run openssl req -x509 -newkey rsa:4096 -out too_large_cert.pem -sha256 -days 3650 -nodes -subj '/C=01/ST=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/L=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/O=0123456789012345678901234567890123456789012345678901234567890123/OU=0123456789012345678901234567890123456789012345678901234567890123/CN=0123456789012345678901234567890123456789012345678901234567890123/CN=0123456789012345678901234567890123456789012345678901234567890123' > /dev/null 2>&1
    assert_success "Generate too large certificate with OpenSSL"
  resp=$("$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i 100 -l too_large_cert -A opaque-x509-certificate --in too_large_cert.pem --informat PEM 2>&1)
  ret=$?
  if [ $ret -ne 0 ]; then
    if [[ $resp == *"Failed to store opaque object: Not enough space to store data"* ]]; then
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i 100 -l too_large_cert -A opaque-x509-certificate --with-compression --in too_large_cert.pem --informat PEM
        assert_success "Import compressed X509 certificate"
    else
      echo ""$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-opaque -i 100 -l too_large_cert -A opaque-x509-certificate --in too_large_cert.pem --informat PEM"
      echo $resp
    fi
  else
    echo "Imported too large certificate raw" >&3
  fi
  set -e
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-opaque -i 100 --outformat=PEM --out too_large_cert_out.pem
    assert_success "Get too large certificate"
  run cmp too_large_cert.pem too_large_cert_out.pem
    assert_success "Compare imported and read certificate"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i 100 -t opaque
    assert_success "Delete too large certificate"

}

@test "HMAC Key tests" {
    [[ "$HMAC_KEY_TESTS" == "true" ]] || skip "skipping right now"


  if [ -e yubihsm-shell_test_dir ]; then
    rm -rf yubihsm-shell_test_dir
  fi
  mkdir yubihsm-shell_test_dir; cd yubihsm-shell_test_dir
  echo test signing data > data.txt

  echo "hmac-sha1" >&3
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-hmac-key -i 0 -l hmackey -d 1,2,3 -c sign-hmac -A hmac-sha1
    assert_success "Generate HMAC-SHA1 key"
  keyid=$(echo "$output" | tail -1 | awk '{print $4}')
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t hmac-key
    assert_success "get-object-info"
    assert_output --partial "id: "$keyid"" 
    assert_output --partial "type: hmac-key" 
    assert_output --partial "algorithm: hmac-sha1" 
    assert_output --partial "label: \"hmackey\""
    assert_output --partial "domains: 1:2:3"
    assert_output --partial "origin: generated"
    assert_output --partial "sign-hmac"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t hmac-key
    assert_success "Delete HMAC key"
  echo "hmac-sha256" >&3
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-hmac-key -i 0 -l hmackey -d 1,2,3 -c sign-hmac -A hmac-sha256
    assert_success "Generate HMAC-SHA256 key"
  keyid=$(echo "$output" | tail -1 | awk '{print $4}')
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t hmac-key
    assert_success "get-object-info"
    assert_output --partial "id: "$keyid"" 
    assert_output --partial "type: hmac-key" 
    assert_output --partial "algorithm: hmac-sha256" 
    assert_output --partial "label: \"hmackey\""
    assert_output --partial "domains: 1:2:3"
    assert_output --partial "origin: generated"
    assert_output --partial "sign-hmac"
  
  echo "hmac-sha384" >&3
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-hmac-key -i 0 -l hmackey -d 1,2,3 -c sign-hmac -A hmac-sha384
    assert_success "Generate HMAC-SHA384 key"
  keyid=$(echo "$output" | tail -1 | awk '{print $4}')
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t hmac-key
    assert_success "get-object-info"
    assert_output --partial "id: "$keyid"" 
    assert_output --partial "type: hmac-key" 
    assert_output --partial "algorithm: hmac-sha384" 
    assert_output --partial "label: \"hmackey\""
    assert_output --partial "domains: 1:2:3"
    assert_output --partial "origin: generated"
    assert_output --partial "sign-hmac"
  echo "hmac-sha512" >&3
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-hmac-key -i 0 -l hmackey -d 1,2,3 -c sign-hmac -A hmac-sha512
    assert_success "Generate HMAC-SHA512 key"
  keyid=$(echo "$output" | tail -1 | awk '{print $4}')
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t hmac-key
    assert_success "get-object-info"
    assert_output --partial "id: "$keyid"" 
    assert_output --partial "type: hmac-key" 
    assert_output --partial "algorithm: hmac-sha512" 
    assert_output --partial "label: \"hmackey\""
    assert_output --partial "domains: 1:2:3"
    assert_output --partial "origin: generated"
    assert_output --partial "sign-hmac"
}

@test "OTP AEAD Key tests" {
    [[ "$OTP_AEAD_TESTS" == "true" ]] || skip "skipping right now"

  if [ -e yubihsm-shell_test_dir ]; then
    rm -rf yubihsm-shell_test_dir
  fi
  mkdir yubihsm-shell_test_dir; cd yubihsm-shell_test_dir
  echo test signing data > data.txt

  echo "AEAD Key AES-128" >&3
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-otp-aead-key -i 0 -l aeadkey -d 1,2,3 -c randomize-otp-aead -A aes128-yubico-otp --nonce 0x01020304
    assert_success "Generate Key"
  keyid=$(echo "$output" | tail -1 | awk '{print $5}')
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t otp-aead-key
    assert_success "Get object info"
    assert_output --partial "id: "$keyid"" 
    assert_output --partial "type: otp-aead-key" 
    assert_output --partial "algorithm: aes128-yubico-otp" 
    assert_output --partial "label: \"aeadkey\""
    assert_output --partial "domains: 1:2:3"
    assert_output --partial "origin: generated"
    assert_output --partial "capabilities: randomize-otp-aead"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a randomize-otp-aead -i "$keyid"
    assert_success "Randomize OTP AEAD"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t otp-aead-key
    assert_success "Delete key"

  echo "AEAD Key AES-192" >&3
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-otp-aead-key -i 0 -l aeadkey -d 1,2,3 -c randomize-otp-aead -A aes192-yubico-otp --nonce 0x01020304
    assert_success "Generate key"
  keyid=$(echo "$output" | tail -1 | awk '{print $5}')
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t otp-aead-key
    assert_success "Get object info"
    assert_output --partial "id: "$keyid"" 
    assert_output --partial "type: otp-aead-key" 
    assert_output --partial "algorithm: aes192-yubico-otp" 
    assert_output --partial "label: \"aeadkey\""
    assert_output --partial "domains: 1:2:3"
    assert_output --partial "origin: generated"
    assert_output --partial "capabilities: randomize-otp-aead"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a randomize-otp-aead -i "$keyid"
    assert_success "Randomize OTP AEAD"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t otp-aead-key
    assert_success "Delete key"

  echo "AEAD Key AES-256" >&3
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-otp-aead-key -i 0 -l aeadkey -d 1,2,3 -c randomize-otp-aead -A aes256-yubico-otp --nonce 0x01020304
    assert_success "Generate key"
  keyid=$(echo "$output" | tail -1 | awk '{print $5}')
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t otp-aead-key
    assert_success "Get object info"
    assert_output --partial "id: "$keyid"" 
    assert_output --partial "type: otp-aead-key" 
    assert_output --partial "algorithm: aes256-yubico-otp" 
    assert_output --partial "label: \"aeadkey\""
    assert_output --partial "domains: 1:2:3"
    assert_output --partial "origin: generated"
    assert_output --partial "capabilities: randomize-otp-aead"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a randomize-otp-aead -i "$keyid"
    assert_success "Randomize OTP AEAD"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t otp-aead-key
    assert_success "Delete key"
}

@test "Template tests" {
    [[ "$TEMPLATE_TESTS" == "true" ]] || skip "skipping right now"

    
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-template -i 20 -l "SSH_Template" -d 1 -A template-ssh --in template.dat
    assert_success "Import template"

  id=$(echo "$output" | grep "Stored Template object" | awk '{print $4}')

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$id" -t template
    assert_success "Get object info"
    assert_output --partial "id: "$id""
    assert_output --partial "type: template"
    assert_output --partial "algorithm: template-ssh"
    assert_output --partial "label: \"SSH_Template\""
    assert_output --partial "domains: 1"
    assert_output --partial "origin: imported"

  #This command doesn't work right now. 
  #run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" --authkey=0x0001 -p password -a sign-ssh-certificate -i 10 --template-id 20 -A rsa-pkcs1-sha256 --in req.dat --out ./id_rsa-cert.pub
    #assert_success "sign request"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-template -i "$id"
      assert_success "Get template"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$id" -t template
      assert_success "Delete template"

    

  #rm resp.txt
  #rm template.txt
}

@test "Wrap Keys tests" {
    [[ "$WRAP_KEYS_TESTS" == "true" ]] || skip "skipping right now"


  if [ -e yubihsm-shell_test_dir ];then
    rm -rf yubihsm-shell_test_dir
  fi
  mkdir yubihsm-shell_test_dir; cd yubihsm-shell_test_dir
  echo test signing data > data.txt

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a reset
    assert_success "Reset device"
  sleep 3
  
  local eckey=100
  local aeskey=200
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-asymmetric-key -i "$eckey" -l eckey -d 1 -c exportable-under-wrap,sign-ecdsa -A ecp224
    assert_success "Generate EC Key to wrap"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
    assert_success "Get object info"
    assert_output --partial "sequence: 0"
    assert_output --partial "origin: generated"

  echo "aes128-ccm-wrap" >&3

  #Generate key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-wrap-key -i 0 -l wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap -A aes128-ccm-wrap
    assert_success "Generate wrap key"
  keyid=$(echo "$output" | awk '/Generated Wrap key/ {print $4}')
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t wrap-key
    assert_success "Get object info"
    assert_output --partial "algorithm: aes128-ccm-wrap"
    assert_output --partial "length: 24"

  #Import key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-pseudo-random --count 16
    assert_success "Get random 16 bytes"
  wrapkey=$(echo "$output" | tail -n 1)
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-wrap-key -i 0 -l imported_wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap --in="$wrapkey"
    assert_success "Import wrap key"

  import_keyid=$(echo "$output" | awk '/Stored Wrap key/ {print $4}') #Kanske fel output att använda, tidigare?
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$import_keyid" -t wrap-key
    assert_success "Get object info"
    assert_output --partial "algorithm: aes128-ccm-wrap"
    assert_output --partial "length: 24"
    assert_output --partial "origin: imported"

  #Wrap and unwrap with generated wrap key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-wrapped --wrap-id "$keyid" -i 100 -t asymmetric-key --out key.gen_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
    assert_success "Delete EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-wrapped --wrap-id "$keyid" --in key.gen_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
    assert_success "Get object info"
    assert_output --partial "sequence: 1"
    assert_output --partial "origin: generated:imported_wrapped"
    assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
    assert_success "Perform signature with imported wrapped key"
  
  #Wrap and unwrap objects with imported wrap key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-wrapped --wrap-id "$import_keyid" -i 100 -t asymmetric-key --out key.imp_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
    assert_success "Delete EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-wrapped --wrap-id "$import_keyid" --in key.imp_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
    assert_success "Get object info"
    assert_output --partial "sequence: 2"
    assert_output --partial "origin: generated:imported_wrapped"
    assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
    assert_success "Perform signature with imported wrapped key"
  
  #Clean up
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t wrap-key
    assert_success "Delete generated wrap key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$import_keyid" -t wrap-key
    assert_success "Delete imported wrap key"
  run rm key.gen_wrapped key.imp_wrapped
    assert_success "Deleted generated and imported wrap keys"
  
  echo "aes192-ccm-wrap" >&3

  #Generate key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-wrap-key -i 0 -l wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap -A aes192-ccm-wrap
    assert_success "Generate wrap key"
  keyid=$(echo "$output" | awk '/Generated Wrap key/ {print $4}')
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t wrap-key
    assert_success "Get object info"
    assert_output --partial "algorithm: aes192-ccm-wrap"
    assert_output --partial "length: 32"

  #Import key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-pseudo-random --count 24
    assert_success "Get random 16 bytes"
  wrapkey=$(echo "$output" | tail -n 1)
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-wrap-key -i 0 -l imported_wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap --in="$wrapkey"
    assert_success "Import wrap key"
  import_keyid=$(echo "$output" | awk '/Stored Wrap key/ {print $4}') #Kanske fel output att använda, tidigare?
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$import_keyid" -t wrap-key
    assert_success "Get object info"
    assert_output --partial "algorithm: aes192-ccm-wrap"
    assert_output --partial "length: 32"
    assert_output --partial "origin: imported"

  #Wrap and unwrap objects with generated wrap key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-wrapped --wrap-id "$keyid" -i 100 -t asymmetric-key --out key.gen_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
    assert_success "Delete EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-wrapped --wrap-id "$keyid" --in key.gen_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
    assert_success "Get object info"
    assert_output --partial "sequence: 3"
    assert_output --partial "origin: generated:imported_wrapped"
    assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
    assert_success "Perform signature with imported wrapped key"
  
  #Wrap and unwrap objects with imported wrap key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-wrapped --wrap-id "$import_keyid" -i 100 -t asymmetric-key --out key.imp_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
    assert_success "Delete EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-wrapped --wrap-id "$import_keyid" --in key.imp_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
    assert_success "Get object info"
    assert_output --partial "sequence: 4"
    assert_output --partial "origin: generated:imported_wrapped"
    assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
    assert_success "Perform signature with imported wrapped key"
  
  #Clean up
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t wrap-key
    assert_success "Delete generated wrap key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$import_keyid" -t wrap-key
    assert_success "Delete imported wrap key"
  run rm key.gen_wrapped key.imp_wrapped
    assert_success "Delete generated and imported wrap keys"
  
  echo "aes256-ccm-wrap" >&3
  #Generate key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-wrap-key -i 0 -l wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap -A aes256-ccm-wrap
    assert_success "Generate wrap key"
  keyid=$(echo "$output" | awk '/Generated Wrap key/ {print $4}')
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t wrap-key
    assert_success "Get object info"
    assert_output --partial "algorithm: aes256-ccm-wrap"
    assert_output --partial "length: 40"
  
  #Import key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-pseudo-random --count 32
    assert_success "Get random 16 bytes"
  wrapkey=$(echo "$output" | tail -n 1)
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-wrap-key -i 0 -l imported_wrapkey -d 1 -c export-wrapped,import-wrapped --delegated sign-ecdsa,exportable-under-wrap --in="$wrapkey"
    assert_success "Import wrap key"
  import_keyid=$(echo "$output" | awk '/Stored Wrap key/ {print $4}') #Kanske fel output att använda, tidigare?
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$import_keyid" -t wrap-key
    assert_success "Get object info"
    assert_output --partial "algorithm: aes256-ccm-wrap"
    assert_output --partial "length: 40"
    assert_output --partial "origin: imported"

  #Wrap and unwrap objects with generated wrap key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-wrapped --wrap-id "$keyid" -i 100 -t asymmetric-key --out key.gen_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
    assert_success "Delete EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-wrapped --wrap-id "$keyid" --in key.gen_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
    assert_success "Get object info"
    assert_output --partial "sequence: 5"
    assert_output --partial "origin: generated:imported_wrapped"
    assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
    assert_success "Perform signature with imported wrapped key"
  
  #Wrap and unwrap with imported wrap key
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-wrapped --wrap-id "$import_keyid" -i 100 -t asymmetric-key --out key.imp_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
    assert_success "Delete EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-wrapped --wrap-id "$import_keyid" --in key.imp_wrapped
    assert_success "Wrap EC key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
    assert_success "Get object info"
    assert_output --partial "sequence: 6"
    assert_output --partial "origin: generated:imported_wrapped"
    assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
    assert_success "Perform signature with imported and wrapped key"
  
  #Clean up
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t wrap-key
    assert_success "Delete generated wrap key"
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$import_keyid" -t wrap-key
    assert_success "Delete imported wrap key"
  run rm key.gen_wrapped key.imp_wrapped
    assert_success "Delete generated and imported wrap keys"
  

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-device-info
  assert_success "Get device info"

  if [[ "$output" != *"aes-kwp"* ]]; then
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete object"

    skip "Device does not support aes-kwp, skipping these tests."
  fi
  aes_enabled=false
  if [[ "$output" == *"aes-kwp"* ]]; then
    aes_enabled=true
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-symmetric-key -i "$aeskey" -l aeskey -d 1 -c exportable-under-wrap,encrypt-cbc,decrypt-cbc -A aes128
      assert_success "Generate AES key to wrap"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-pseudo-random --count 16
      assert_success "Get random 16 bytes"
    iv=$(echo "$output" | tail -n 1)
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-pseudo-random --count 32
      assert_success "Get random 32 bytes for encryption"
    data=$(echo "$output" | tail -n 1)
  fi
  RSA_KEYSIZE=("2048" "3072" "4096")
  seq_ec=6
  seq_aes=0

  for k in ${RSA_KEYSIZE[@]}; do
    echo "RSA"$k"" >&3
    if [[ "$k" != "2048" ]]; then
      echo "This may take a while..." >&3
    fi
    #Generate RSA wrap keys
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-wrap-key -i 0 -l wrapkey -c import-wrapped  --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc -A rsa"$k"
      assert_success "Generate RSA wrap key"
    keyid=$(echo "$output" | awk '/Generated Wrap key/ {print $4}')
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$keyid" -t wrap-key
      assert_success "Get object into"
      assert_output --partial "algorithm: rsa"$k""
      assert_output --partial "origin: generated"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-public-key -i "$keyid" -t wrap-key --out public_wrapkey.pem
      assert_success "Export rsa public wrap key"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-public-wrapkey -i "$keyid" -c export-wrapped --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc --in public_wrapkey.pem
      assert_success "Import RSA public wrap key"
    run rm public_wrapkey.pem
      assert_success "Delete wrapkey"
    
    #Wrap and unwrap EC object with generated wrap key
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-rsa-wrapped --wrap-id "$keyid" -i "$eckey" -t asymmetric-key --out rsawrapped.object
      assert_success "Export wrapped EC object"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete EC key"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-rsa-wrapped --wrap-id "$keyid" --in rsawrapped.object
      assert_success "Import wrapped EC object"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
      assert_success "Get object info"
    seq_ec=$((seq_ec+1))
    assert_output --partial "sequence: "$seq_ec""
    assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
      assert_success "Perform signature with imported wrapped EC key"
    run rm rsawrapped.object
      assert_success "Removed RSA wrapped object"
    
    #Wrap and unwrap EC key material with generated RSA wrap key
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-rsa-wrapped-key --wrap-id "$keyid" -i "$eckey" -t asymmetric-key --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --out rsawrapped.key
      assert_success "Export wrapped EC key material"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete EC key"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-rsa-wrapped-key --wrap-id "$keyid" -i "$eckey" -t asymmetric-key -A ecp224 -c exportable-under-wrap,sign-ecdsa --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --in rsawrapped.key
      assert_success "Import wrapped EC key material"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
      assert_success "Get object info"
      seq_ec=$((seq_ec+1))
      assert_output --partial "sequence: "$seq_ec""
      assert_output --partial "origin: imported:imported_wrapped"
      assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
      assert_success "Perform signature with imported wrapped EC key"
    run rm rsawrapped.key
      assert_success "Removed RSA wrapped key"
    
    if [[ "$aes_enabled" = true ]]; then
      #Wrap and unwrap AES object with generated RSA wrap key
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-rsa-wrapped --wrap-id "$keyid" -i "$aeskey" -t symmetric-key --out rsawrapped.object
        assert_success "Export wrapped AES object"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$aeskey" -t symmetric-key
        assert_success "Deleta AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-rsa-wrapped --wrap-id "$keyid" --in rsawrapped.object
        assert_success "Import wrapped AES object"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$aeskey" -t symmetric-key
        assert_success "Get object info"
        seq_aes=$((seq_aes+1))
        assert_output --partial "sequence: "$seq_aes""
        assert_output --partial "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a encrypt-aescbc -i "$aeskey" --iv "$iv" --in "$data" --out data.enc
        assert_success "Perform encryption with imported wrapped AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Perform decryption with imported wrapped AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Decryption succeeded"
        last_line_of_output=$(echo "$output" | tail -n 1)
        assert_equal "$last_line_of_output" "$data" #Line 288-293
      run rm rsawrapped.object data.enc
        assert_success "Removed RSA wrapped object and encrypted data"
      
      #Wrap and unwrap AES key material with generated RSA wrap key
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-rsa-wrapped-key --wrap-id "$keyid" -i "$aeskey" -t symmetric-key --oaep rsa-oaep-sha384 --mgf1 mgf1-sha1 --out rsawrapped.key
        assert_success "Export wrapped AES key material"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$aeskey" -t symmetric-key
        assert_success "Delete AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-rsa-wrapped-key --wrap-id "$keyid" -i "$aeskey" -t symmetric-key -A aes128 -c exportable-under-wrap,decrypt-cbc,encrypt-cbc --oaep rsa-oaep-sha384 --mgf1 mgf1-sha1 --in rsawrapped.key
        assert_success "Import wrapped AES key material"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$aeskey" -t symmetric-key
        assert_success "Get object info"
        seq_aes=$((seq_aes+1))
        assert_output --partial "sequence: "$seq_aes""
        assert_output --partial "origin: imported:imported_wrapped"
        assert_output --partial "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
        assert_success "Perform signature with imported wrapped EC key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a encrypt-aescbc -i "$aeskey" --iv "$iv" --in "$data" --out data.enc
        assert_success "Perform encryption with imported wrapped AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Perform decryption with imported wrapped AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Decryption succeeded"
        last_line_of_output=$(echo "$output" | tail -n 1)
        assert_equal "$last_line_of_output" "$data" #Line 310-315
      run rm rsawrapped.key data.enc
        assert_success "Removed RSA wrapped key and encrypted data"
    fi

    #Import RSA wrap keys
    run openssl genrsa -out keypair.pem "$k"
      assert_success "Generate RSA key with openssl"
    run openssl rsa -in keypair.pem -pubout -out key.pub
      assert_success "Extract public key from openssl generated keypair"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-rsa-wrapkey -i 0 -d 1 -c import-wrapped --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc --in keypair.pem
      assert_success "Import RSA wrap key"
    import_keyid=$(echo "$output" | awk '/Stored Wrap key/ {print $4}') #Kanske fel output att använda, tidigare?
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$import_keyid" -t wrap-key
      assert_success "Get object info"
      assert_output --partial "algorithm: rsa"$k""
      assert_output --partial "origin: imported"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-public-wrapkey -i "$import_keyid" -c export-wrapped --delegated exportable-under-wrap,sign-ecdsa,encrypt-cbc,decrypt-cbc --in key.pub
      assert_success "Import RSA public wrap key"
    run rm keypair.pem key.pub
      assert_success "Remove keypairs"
    
    #Wrap and unwrap EC object with imported RSA wrap key
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-rsa-wrapped --wrap-id "$import_keyid" -i "$eckey" -t asymmetric-key --out rsawrapped.object
      assert_success "Export wrapped EC object"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete EC key"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-rsa-wrapped --wrap-id "$import_keyid" --in rsawrapped.object
      assert_success "Import wrapped EC objects"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
      assert_success "Get object info"
      seq_ec=$((seq_ec+1))
      assert_output --partial "sequence: "$seq_ec""
      assert_output --partial "origin: imported:imported_wrapped"
      assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
      assert_success "Perform signature with imported wrapped EC key"
    run rm rsawrapped.object
      assert_success "Delete RSA wrapped object"
    
    #Wrap and unwrap EC key material with imported RSA wrap key
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-rsa-wrapped-key --wrap-id "$import_keyid" -i "$eckey" -t asymmetric-key --oaep rsa-oaep-sha512 --mgf1 mgf1-sha512 --out rsawrapped.key
      assert_success "Export wrapped EC key material"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$eckey" -t asymmetric-key
      assert_success "Delete EC key"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-rsa-wrapped-key --wrap-id "$import_keyid" -i "$eckey" -t asymmetric-key -A ecp224 -c exportable-under-wrap,sign-ecdsa --oaep rsa-oaep-sha512 --mgf1 mgf1-sha512 --in rsawrapped.key
      assert_success "Import wrapped EC key material"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$eckey" -t asymmetric-key
      assert_success "Get object info"
      seq_ec=$((seq_ec+1))
      assert_output --partial "sequence: "$seq_ec""
      assert_output --partial "origin: imported:imported_wrapped"
      assert_output --partial "capabilities: exportable-under-wrap:sign-ecdsa"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
      assert_success "Perform signature with imported wrapped EC key"
    run rm rsawrapped.key
      assert_success "Removed RSA wrapped key"

    if [[ "$aes_enabled" = true ]]; then
      #Wrap and unwrap AES object with imported RSA wrap key
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-rsa-wrapped --wrap-id "$import_keyid" -i "$aeskey" -t symmetric-key --out rsawrapped.object
        assert_success "Export wrapped AES object"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$aeskey" -t symmetric-key
        assert_success "Deleta AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-rsa-wrapped --wrap-id "$import_keyid" --in rsawrapped.object
        assert_success "Import wrapped AES object"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$aeskey" -t symmetric-key
        assert_success "Get object info"
        seq_aes=$((seq_aes+1))
        assert_output --partial "sequence: "$seq_aes""
        assert_output --partial "origin: imported:imported_wrapped"
        assert_output --partial "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a encrypt-aescbc -i "$aeskey" --iv "$iv" --in "$data" --out data.enc
        assert_success "Perform encryption with imported wrapped AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Perform decryption with imported wrapped AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Decryption succeeded"
        last_line_of_output=$(echo "$output" | tail -n 1)
        assert_equal "$last_line_of_output" "$data" #Line 369-375
      run rm rsawrapped.object data.enc
        assert_success "Removed RSA wrapped object and encrypted data"
      
      #Wrap and unwrap AES key material with imported RSA wrap key
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-rsa-wrapped-key --wrap-id "$import_keyid" -i "$aeskey" -t symmetric-key --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --out rsawrapped.key
        assert_success "Export wrapped AES key material"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$aeskey" -t symmetric-key
        assert_success "Delete AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-rsa-wrapped-key --wrap-id "$import_keyid" -i "$aeskey" -t symmetric-key -A aes128 -c exportable-under-wrap,decrypt-cbc,encrypt-cbc --oaep rsa-oaep-sha1 --mgf1 mgf1-sha384 --in rsawrapped.key
        assert_success "Import wrapped AES key materiak"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i "$aeskey" -t symmetric-key
        assert_success "Get object info"
        seq_aes=$((seq_aes+1))
        assert_output --partial "sequence: "$seq_aes""
        assert_output --partial "origin: imported:imported_wrapped"
        assert_output --partial "capabilities: decrypt-cbc:encrypt-cbc:exportable-under-wrap"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a sign-ecdsa -i "$eckey" -A ecdsa-sha1 --in data.txt
        assert_success "Perform encryption with imported wrapped EC key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a encrypt-aescbc -i "$aeskey" --iv "$iv" --in "$data" --out data.enc
        assert_success "Perform encryption with imported wrapped AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Perform decryption with imported wrapped AES key"
      run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a decrypt-aescbc -i "$aeskey" --iv "$iv" --in data.enc
        assert_success "Decryption succeeded"
        last_line_of_output=$(echo "$output" | tail -n 1)
        assert_equal "$last_line_of_output" "$data" #Line 390-397
      run rm rsawrapped.key data.enc
        assert_success "Removed RSA wrapped key and encrypted data"

    fi
    #Clean up
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t wrap-key
      assert_success "Delete generated RSA wrap key"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t public-wrap-key
      assert_success "Delete generated RSA public wrap key"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$import_keyid" -t wrap-key
      assert_success "Delete imported RSA wrap key"
    run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$import_keyid" -t public-wrap-key
      assert_success "Delete imported RSA public wrap key"
  done
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a reset
    assert_success "Reset device"
  sleep 3 #Connection crashes otherwise (over usb)

}

@test "List Objects" {
    [[ "$LIST_TESTS" == "true" ]] || skip "skipping right now"


  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-asymmetric-key -i 100 -l ecKey -d 5,8,13 -c sign-ecdsa,derive-ecdh,sign-attestation-certificate -A ecp224
      assert_success "Generate EC key for testing"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a list-objects -A any -t any -i 100
      assert_success "List objects by ID"
      assert_output --partial "Found 1 object(s)"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a list-objects -A any -t asymmetric-key
      assert_success "List objects by type"
      assert_output --partial "Found 1 object(s)"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a list-objects -A any -t any -d 5,8,13
      assert_success "List objects by domain"
      assert_output --partial "Found 2 object(s)"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a list-objects -A any -t any -c sign-ecdsa,derive-ecdh,sign-attestation-certificate
      assert_success "List objects by capabilities"
      assert_output --partial "Found 2 object(s)"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a list-objects -A ecp224 -t any
      assert_success "List objects by algorithm"
      assert_output --partial "Found 1 object(s)"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a list-objects -A any -t any -l ecKey
      assert_success "List objects by label"
      assert_output --partial "Found 1 object(s)"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i 100 -t asymmetric-key
      assert_success "Delete key"
}

@test "Label Size" {
    [[ "$LABEL_TESTS" == "true" ]] || skip "skipping right now"


  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-asymmetric-key -i 300 -d 5,8,13 -c sign-ecdsa -A ecp224
    assert_success "Create key with no label"
    
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i 300 -t asymmetric-key
    assert_success "Get info for key with no label"
    assert_output --partial "label: \"\""

    # --- Test with 39-character label ---
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-asymmetric-key -i 200 -l abcdefghijklmnopqrstuvwxyz0123456789abc -d 5,8,13 -c sign-ecdsa -A ecp224
    assert_success "Create object with 39-character label"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a get-object-info -i 200 -t asymmetric-key
    assert_success "Get info for 39-character label"
    assert_output --partial "label: \"abcdefghijklmnopqrstuvwxyz0123456789abc\""

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a list-objects -A any -t any -l abcdefghijklmnopqrstuvwxyz0123456789abc
    assert_success "List objects with 39-character label"
    assert_output --partial "Found 1 object(s)"

    # --- Test with 40-character label ---
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-asymmetric-key -i 100 -l abcdefghijklmnopqrstuvwxyz0123456789abcd -d 5,8,13 -c sign-ecdsa -A ecp224
    assert_success "Create object with 40-character label"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a list-objects -A any -t any -l abcdefghijklmnopqrstuvwxyz0123456789abcd
    assert_success "List objects with 40-character label"
    assert_output --partial "Found 1 object(s)"

    # --- Test that 41-character label FAILS ---
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a generate-asymmetric-key -i 400 -l "abcdefghijklmnopqrstuvwxyz0123456789abcde" -d "5,8,13" -c "sign-ecdsa" -A "ecp224"
    assert_failure
    assert_output --partial "Invalid argument to a function"

    # --- Test listing a non-existent label ---
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a list-objects -A any -t any -l doesnotexist
    assert_success "List objects by non-existent label"
    assert_output --partial "Found 0 object(s)"

    # --- Clean up created objects ---
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i 100 -t asymmetric-key
    assert_success "Clean up key 100"
    
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i 200 -t asymmetric-key
    assert_success "Clean up key 200"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i 300 -t asymmetric-key
    assert_success "Clean up key 300"
}

@test "Authentication" {
    [[ "$AUTHENTICATION_TESTS" == "true" ]] || skip "skipping right now"


  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-authentication-key -i 0 -l authkey -d 1,2,3 -c all --delegated all --new-password foo123
      assert_success "Create new authentication key"

  local keyid
  keyid=$(echo "$output" | tail -1 | awk '{print $4}')

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" --authkey $keyid -p foo123 -a get-object-info -i 1 -t authentication-key
      assert_success "Authenticate with new authentication key"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i "$keyid" -t authentication-key
      assert_success "Delete authentication key"
}