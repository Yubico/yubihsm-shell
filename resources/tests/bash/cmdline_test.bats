load 'test_helper/bats-support/load'
load 'test_helper/bats-assert/load'

setup_file() {
  if [ -e yubihsm-shell_test_dir ];
  then
      rm -rf yubihsm-shell_test_dir
  fi
  echo "--- Configuration via Environment Variables ---" >&3
  echo "YUBIHSM_PATH: path to the yubihsm-shell command line tool - using default connector." >&3
  echo "SPECIFIED_CONNECTOR:      path to the yubihsm-shell command line tool - using specified connector" >&3
  echo "-----------------------------------------------" >&3
  echo "These tests will reset your HSM" >&3
  echo "Press Enter to continue or Ctrl-C + enter to abort" >&3
  read -p "" >&3



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
  #skip "skipping right now"

  run ./test_edkey.sh
    assert_success "ED Key tests passed"
}

@test "EC Key tests" {
  #skip "skipping right now"

  if [ -z ${DOCKER_IMAGE} ] || [ ${DOCKER_IMAGE} != "centos:7" ]; then
      # This DOCKER_IMAGE environment variable is set in the build_and_test.yml github workflow.
      ./test_eckey.sh
  else
      skip "Skipping EC key tests on centos:7 as it does not have the required openssl version"
  fi
}

@test "RSA Key tests" {
  #skip "skipping right now"

  run ./test_rsakey.sh
    assert_success "RSA Key tests passed"
}

@test "HMAC Key tests" {
  #skip "skipping right now"

  run ./test_hmackey.sh
    assert_success "HMAC Key tests passed"
}

@test "OTP AEAD Key tests" {
  #skip "skipping right now"

  run ./test_otpaeadkey.sh
    assert_success "OTP AEAD Key tests passed"
}



@test "Template tests" {
  skip "skipping right now as it is broken"
    
  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-template -i 20 -l "SSH_Template" -d 1 -A template-ssh --in template.dat
    assert_success "Import template"

  local id
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



@test "List Objects" {
  #skip "skipping right now as im not there yet"

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
  #skip "skipping right now as im not there yet"

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
  #skip "skipping right now"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a put-authentication-key -i 0 -l authkey -d 1,2,3 -c all --delegated all --new-password foo123
      assert_success "Create new authentication key"

  local keyid
  keyid=$(echo "$output" | tail -1 | awk '{print $4}')

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" --authkey $keyid -p foo123 -a get-object-info -i 1 -t authentication-key
      assert_success "Authenticate with new authentication key"

  run "$BIN" "$c_var" "$SPECIFIED_CONNECTOR" -p password -a delete-object -i $keyid -t authentication-key
      assert_success "Delete authentication key"
}

@test "Wrap Keys tests" {
  #skip "skipping right now as it takes a while to run"

  run ./test_wrapkey.sh
  assert_success "Wrap Key tests passed"
}