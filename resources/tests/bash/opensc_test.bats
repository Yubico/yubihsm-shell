load 'test_helper/bats-support/load'
load 'test_helper/bats-assert/load'

setup_file() {
  echo "--- Configuration via Environment Variables ---" >&3
  echo "MODULE: Path to the PKCS#11 module, default /usr/local/lib/yubihsm_pkcs11.so (Linux) or /usr/local/lib/yubihsm_pkcs11.dylib (Mac)" >&3
  echo "EDIT_PATH: (Windows/Msys only) Path to directory where pkcs11-tool.exe and libyubihsm is located if not in default locations. Use delimiter ":". Example: export EDIT_PATH='C:\Path\To\OpenSC\tools:C:\Path\To\YubiHSM Shell\bin" >&3
  echo "CONFIG_FILE: Path to the yubihsm_pkcs11 configuration file, default is in current directory" >&3
  echo "-----------------------------------------------" >&3
  echo "" >&3

  export EC_CURVES="secp224r1 secp256r1 secp384r1 secp521r1 secp256k1"
  export pkcs11="pkcs11-tool"
  export RSA_LENGTHS="2048 3072 4096"
  export YUBIHSM_PKCS11_CONF=${CONFIG_FILE:-"$(pwd)/yubihsm_pkcs11.conf"}
  local default_module_path="/usr/local/lib/yubihsm_pkcs11.dylib" #Default path for Mac
  os=$(uname -o)

  if ! { [[ "$os" == "Linux" ]] && grep -q 'Fedora' /etc/os-release 2>/dev/null; }; then
    EC_CURVES="$EC_CURVES brainpoolP256r1 brainpoolP384r1 brainpoolP512r1"
  fi
  
  if [[ "$os" == "Msys" ]]; then
    echo "This script expects that the pkcs11-tool from OpenSC is installed under "C:\Program Files\OpenSC Project\OpenSC\tools" and that libyubihsm.dll is installed under "C:\Program Files\Yubico\YubiHSM Shell\bin" "
    echo "If that is not the case, please point to the correct locations via the environment variable EDIT_PATH"
    pkcs11="pkcs11-tool.exe"
    default_module_path="C:\Program Files\Yubico\YubiHSM Shell\bin\pkcs11\yubihsm_pkcs11.dll"
    export MSYS2_ARG_CONV_EXCL=*

    if ! [ -z "$EDIT_PATH" ]; then
        export PATH="$PATH:"$EDIT_PATH""
    else
        # Adds pkcs11-tool and yubihsm-shell to PATH
        export PATH="$PATH:C:\Program Files\OpenSC Project\OpenSC\tools:C:\Program Files\Yubico\YubiHSM Shell\bin"
    fi
  elif [[ "$os" == "GNU/LINUX" ]]; then
    default_module_path="/usr/local/lib/yubihsm_pkcs11.so"
  fi

  export MODULE=${MODULE:-$default_module_path}

  echo "--------------------------------" >&3
  echo "Variables Check:" >&3
  echo "Using module: "$MODULE"" >&3
  echo "Using pkcs11: "$pkcs11"" >&3
  echo "EC Curves to test: "$EC_CURVES"" >&3
  echo "RSA Lengths to test: "$RSA_LENGTHS"" >&3 
  echo "--------------------------------" >&3

  echo "These tests will reset your HSM" >&3
  echo "Press Enter to continue or Ctrl-C + enter to abort" >&3
  read -p ""

  if [ -e yubihsm-shell_test_dir ]; then
    rm -rf yubihsm-shell_test_dir
  fi
  mkdir yubihsm-shell_test_dir; cd yubihsm-shell_test_dir
  echo "test signing data" > data.txt
}

@test "EC Curve tests" {

    for curve in $EC_CURVES; do
        echo "Testing curve: "$curve"" >&3
        #Generate key
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --keypairgen --id 1 --key-type EC:"$curve"
            assert_success "Generate EC key with curve $curve"
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --read-object --id 1 --type pubkey --output-file pubkey.der
            assert_success "Get public key of generated key"
            
        #Sign with generated key
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
            assert_success "Sign with generated key and ECDSA-SHA1"
        run openssl dgst -sha1 -verify pubkey.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m ECDSA-SHA256 --signature-format openssl -i data.txt -o data.sig
            assert_success "Sign with generated key and ECDSA-SHA256"
        run openssl dgst -sha256 -verify pubkey.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m ECDSA-SHA384 --signature-format openssl -i data.txt -o data.sig
            assert_success "Sign with generated key and ECDSA-SHA384"
        run openssl dgst -sha384 -verify pubkey.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m ECDSA-SHA512 --signature-format openssl -i data.txt -o data.sig
            assert_success "Sign with generated key and ECDSA-SHA512"
        run openssl dgst -sha512 -verify pubkey.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        
        #Import key
        run openssl ecparam -name "$curve" -genkey -noout -out keypair.pem
            assert_success "Generate keypair with curve "$curve" using openssl"
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --write-object keypair.pem --id 2 --type privkey --usage-sign
            assert_success "Import EC key with curve "$curve""
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --read-object --id 2 --type pubkey --output-file pubkey_imported.der
            assert_success "Get public key of imported key"

        #Sign with imported key
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
            assert_success "Sign with imported key and ECDSA-SHA1"
        run openssl dgst -sha1 -verify pubkey_imported.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m ECDSA-SHA256 --signature-format openssl -i data.txt -o data.sig
            assert_success "Sign with imported key and ECDSA-SHA256"
        run openssl dgst -sha256 -verify pubkey_imported.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m ECDSA-SHA384 --signature-format openssl -i data.txt -o data.sig
            assert_success "Sign with imported key and ECDSA-SHA384"
        run openssl dgst -sha384 -verify pubkey_imported.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m ECDSA-SHA512 --signature-format openssl -i data.txt -o data.sig
            assert_success "Sign with imported key and ECDSA-SHA512"
        run openssl dgst -sha512 -verify pubkey_imported.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"

        #Derive ECDH
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --derive --id 1 --input-file pubkey_imported.der --output-file ecdh_pkcs11.bin
            assert_success "Derive ECDH usin pkcs11-tool"
        run openssl pkeyutl -derive -inkey keypair.pem -peerkey pubkey.der -out ecdh_openssl.bin
            assert_success "Derive ECDH using openssl"
        run cmp ecdh_pkcs11.bin ecdh_openssl.bin
            assert_success "Compare the derived ECDH keys"
        run rm ecdh_pkcs11.bin ecdh_openssl.bin
            assert_success "Delete ECDH keys"

        # Requires writable session? yubihs-pkcs11 only allowed regular users
        #run "$pkcs11" --module ""$MODULE"" --login --pin 0001password --test-ec --id 200 --key-type EC:secp256r1
        #    assert_success "Test EC key with yubihs-pkcs11"

        #Delete keys
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --delete-object --id 1 --type privkey
            assert_success "Delete generated key"
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --delete-object --id 2 --type privkey
            assert_success "Delete imported key"
    done
}

@test "RSA Key tests" {

    run openssl dgst -sha1 -binary -out data.sha1 data.txt
        assert_success "Hash data with SHA1 and OpenSSL"
    run openssl dgst -sha256 -binary -out data.sha256 data.txt
        assert_success "Hash data with SHA256 and OpenSSL"
    run openssl dgst -sha384 -binary -out data.sha384 data.txt
        assert_success "Hash data with SHA384 and OpenSSL"
    run openssl dgst -sha512 -binary -out data.sha512 data.txt
        assert_success "Hash data with SHA512 and OpenSSL"

    for length in $RSA_LENGTHS; do
        echo "Testing RSA key with length: "$length"" >&3

        #Generate key
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --keypairgen --id 1 --key-type rsa:"$length" --usage-sign --usage-decrypt
            assert_success "Generate RSA key with length "$length""
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --read-object --id 1 --type pubkey --output-file pubkey.der
            assert_success "Get public key of generated key"

        #Sign with generated key and RSA-PKCS
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m SHA1-RSA-PKCS -i data.txt -o data.sig
            assert_success "Sign with generated key and SHA1-RSA-PKCS"
        run openssl dgst -sha1 -verify pubkey.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m SHA256-RSA-PKCS -i data.txt -o data.sig
            assert_success "Sign with generated key and SHA256-RSA-PKCS"
        run openssl dgst -sha256 -verify pubkey.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m SHA384-RSA-PKCS -i data.txt -o data.sig
            assert_success "Sign with generated key and SHA384-RSA-PKCS"
        run openssl dgst -sha384 -verify pubkey.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m SHA512-RSA-PKCS -i data.txt -o data.sig
            assert_success "Sign with generated key and SHA512-RSA-PKCS"
        run openssl dgst -sha512 -verify pubkey.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"

        #Sign with generated key and RSA-PSS
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m SHA1-RSA-PKCS-PSS -i data.txt -o data.sig
            assert_success "Sign with generated key and SHA1-RSA-PKCS-PSS"
        run openssl pkeyutl -verify -in data.sha1 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m SHA256-RSA-PKCS-PSS -i data.txt -o data.sig
            assert_success "Sign with generated key and SHA256-RSA-PKCS-PSS"
        run openssl pkeyutl -verify -in data.sha256 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m SHA384-RSA-PKCS-PSS -i data.txt -o data.sig
            assert_success "Sign with generated key and SHA384-RSA-PKCS-PSS"
        run openssl pkeyutl -verify -in data.sha384 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha384
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 1 -m SHA512-RSA-PKCS-PSS -i data.txt -o data.sig
            assert_success "Sign with generated key and SHA512-RSA-PKCS-PSS"
        run openssl pkeyutl -verify -in data.sha512 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha512
            assert_success "Verify signature with openssl"

        #Decrypt with generated key and PKCS1v15
        run openssl rsautl -encrypt -inkey pubkey.der -pubin -in data.txt -out data.enc
            assert_success "Encrypt with openssl using PKCS1v15"
        run "$pkcs11" --module "$MODULE" --decrypt --pin 0001password --id 1 -m RSA-PKCS --input-file data.enc --output-file data.dec
            assert_success "Decrypt using generated key"
        run cmp data.dec data.txt
            assert_success "Compare decrypted data with plain text data"
        run rm data.enc data.dec
            assert_success "Delete test data"

        #Decrypt with generated key and OAEP
        run openssl pkeyutl -encrypt -pubin -inkey pubkey.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -in data.txt -out data.enc
            assert_success "Encrypt with OpenSSL using OAEP and SHA1"
        run "$pkcs11" --module "$MODULE" --decrypt --pin 0001password --id 1 -m RSA-PKCS-OAEP --hash-algorithm=SHA-1 --input-file data.enc --output-file data.dec
            assert_success "Decrypt using generated key with SHA1"
        run cmp data.dec data.txt
            assert_success "Compare decrypted data for SHA1"
        run rm data.enc data.dec
            assert_success "Delete test data for SHA1"
        run openssl pkeyutl -encrypt -pubin -inkey pubkey.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in data.txt -out data.enc
            assert_success "Encrypt with OpenSSL using OAEP and SHA256"
        run "$pkcs11" --module "$MODULE" --decrypt --pin 0001password --id 1 -m RSA-PKCS-OAEP --hash-algorithm=SHA256 --input-file data.enc --output-file data.dec
            assert_success "Decrypt using generated key with SHA256"
        run cmp data.dec data.txt
            assert_success "Compare decrypted data for SHA256"
        run rm data.enc data.dec
            assert_success "Delete test data for SHA256"
        run openssl pkeyutl -encrypt -pubin -inkey pubkey.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha384 -pkeyopt rsa_mgf1_md:sha384 -in data.txt -out data.enc
            assert_success "Encrypt with OpenSSL using OAEP and SHA384"
        run "$pkcs11" --module "$MODULE" --decrypt --pin 0001password --id 1 -m RSA-PKCS-OAEP --hash-algorithm=SHA384 --input-file data.enc --output-file data.dec
            assert_success "Decrypt using generated key with SHA384"
        run cmp data.dec data.txt
            assert_success "Compare decrypted data for SHA384"
        run rm data.enc data.dec
            assert_success "Delete test data for SHA384"
        run openssl pkeyutl -encrypt -pubin -inkey pubkey.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha512 -pkeyopt rsa_mgf1_md:sha512 -in data.txt -out data.enc
            assert_success "Encrypt with OpenSSL using OAEP and SHA512"
        run "$pkcs11" --module "$MODULE" --decrypt --pin 0001password --id 1 -m RSA-PKCS-OAEP --hash-algorithm=SHA512 --input-file data.enc --output-file data.dec
            assert_success "Decrypt using generated key with SHA512"
        run cmp data.dec data.txt
            assert_success "Compare decrypted data for SHA512"
        run rm data.enc data.dec
            assert_success "Delete test data for SHA512"

        #Import key
        run openssl genrsa -out keypair.pem "$length"
            assert_success "Generate key with openssl"
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --write-object keypair.pem --id 2 --type privkey --usage-sign --usage-decrypt
            assert_success "Import RSA"$length" key"
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --read-object --id 2 --type pubkey --output-file pubkey_imported.der
            assert_success "Get public key of imported key"
        
        # Sign with imported key and PKCS
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m SHA1-RSA-PKCS -i data.txt -o data.sig
            assert_success "Sign with imported key and SHA1-RSA-PKCS"
        run openssl dgst -sha1 -verify pubkey_imported.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m SHA256-RSA-PKCS -i data.txt -o data.sig
            assert_success "Sign with imported key and SHA256-RSA-PKCS"
        run openssl dgst -sha256 -verify pubkey_imported.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m SHA384-RSA-PKCS -i data.txt -o data.sig
            assert_success "Sign with imported key and SHA384-RSA-PKCS"
        run openssl dgst -sha384 -verify pubkey_imported.der -signature data.sig data.txt
            assert_success "Verify sgnature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m SHA512-RSA-PKCS -i data.txt -o data.sig
            assert_success "Sign with imported key and SHA512-RSA-PKCS"
        run openssl dgst -sha512 -verify pubkey_imported.der -signature data.sig data.txt
            assert_success "Verify signature with openssl"
        
        # Sign with imported key and RSA-PSS
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m SHA1-RSA-PKCS-PSS -i data.txt -o data.sig
            assert_success "Sign with imported key and SHA1-RSA-PKCS-PSS"
        run openssl pkeyutl -verify -in data.sha1 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_imported.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m SHA256-RSA-PKCS-PSS -i data.txt -o data.sig
            assert_success "Sign with imported key and SHA256-RSA-PKCS-PSS"
        run openssl pkeyutl -verify -in data.sha256 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_imported.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m SHA384-RSA-PKCS-PSS -i data.txt -o data.sig
            assert_success "Sign with imported key and SHA384-RSA-PKCS-PSS"
        run openssl pkeyutl -verify -in data.sha384 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_imported.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha384
            assert_success "Verify signature with openssl"
        run "$pkcs11" --module "$MODULE" --sign --pin 0001password --id 2 -m SHA512-RSA-PKCS-PSS -i data.txt -o data.sig
            assert_success "Sign with imported key and SHA512-RSA-PKCS-PSS"
        run openssl pkeyutl -verify -in data.sha512 -sigfile data.sig -pkeyopt rsa_padding_mode:pss -pubin -inkey pubkey_imported.der -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha512
            assert_success "Verify signature with openssl"

        # Decrypt with imported key and PKCS1v15
        run openssl rsautl -encrypt -inkey pubkey_imported.der -pubin -in data.txt -out data.enc
            assert_success "Encryp with openssl using PKCS1v15"
        run "$pkcs11" --module "$MODULE" --decrypt --pin 0001password --id 2 -m RSA-PKCS --input-file data.enc --output-file data.dec
            assert_success "Decrypt using imported key"
        run cmp data.dec data.txt
            assert_success "Compare decrypted data with plain text data"
        run rm data.enc data.dec
            assert_success "Delete test data"

        # Decrypt with imported key and OAEP
        run openssl pkeyutl -encrypt -pubin -inkey pubkey_imported.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -in data.txt -out data.enc
            assert_success "Encrypt with openssl using OAEP and SHA1"
        run openssl pkeyutl -encrypt -pubin -inkey pubkey_imported.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 -in data.txt -out data.enc
            assert_success "Encrypt with OpenSSL using OAEP and SHA1"
        run "$pkcs11" --module "$MODULE" --decrypt --pin 0001password --id 2 -m RSA-PKCS-OAEP --hash-algorithm=SHA-1 --input-file data.enc --output-file data.dec
            assert_success "Decrypt using imported key with SHA1"
        run cmp data.dec data.txt
            assert_success "Compare decrypted data for SHA1"
        run rm data.enc data.dec
            assert_success "Delete test data for SHA1"
        run openssl pkeyutl -encrypt -pubin -inkey pubkey_imported.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in data.txt -out data.enc
            assert_success "Encrypt with OpenSSL using OAEP and SHA256"
        run "$pkcs11" --module "$MODULE" --decrypt --pin 0001password --id 2 -m RSA-PKCS-OAEP --hash-algorithm=SHA256 --input-file data.enc --output-file data.dec
            assert_success "Decrypt using imported key with SHA256"
        run cmp data.dec data.txt
            assert_success "Compare decrypted data for SHA256"
        run rm data.enc data.dec
            assert_success "Delete test data for SHA256"
        run openssl pkeyutl -encrypt -pubin -inkey pubkey_imported.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha384 -pkeyopt rsa_mgf1_md:sha384 -in data.txt -out data.enc
            assert_success "Encrypt with OpenSSL using OAEP and SHA384"
        run "$pkcs11" --module "$MODULE" --decrypt --pin 0001password --id 2 -m RSA-PKCS-OAEP --hash-algorithm=SHA384 --input-file data.enc --output-file data.dec
            assert_success "Decrypt using imported key with SHA384"
        run cmp data.dec data.txt
            assert_success "Compare decrypted data for SHA384"
        run rm data.enc data.dec
            assert_success "Delete test data for SHA384"
        run openssl pkeyutl -encrypt -pubin -inkey pubkey_imported.der -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha512 -pkeyopt rsa_mgf1_md:sha512 -in data.txt -out data.enc
            assert_success "Encrypt with OpenSSL using OAEP and SHA512"
        run "$pkcs11" --module "$MODULE" --decrypt --pin 0001password --id 2 -m RSA-PKCS-OAEP --hash-algorithm=SHA512 --input-file data.enc --output-file data.dec
            assert_success "Decrypt using imported key with SHA512"
        run cmp data.dec data.txt
            assert_success "Compare decrypted data for SHA512"
        run rm data.enc data.dec
            assert_success "Delete test data for SHA512"
        
        #Delete keys
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --delete-object --id 1 --type privkey
            assert_success "Delete generated key"
        run "$pkcs11" --module "$MODULE" --login --pin 0001password --delete-object --id 2 --type privkey
            assert_success "Delete generated key"
    done
    run rm data.sha1 data.sha256 data.sha384 data.sha512 data.sig data.txt
        assert_success "Delete test data"
    run rm keypair.pem pubkey.der pubkey_imported.der
        assert_success "Delete key files"
}

@test "Compress x509 Certificate" {
    run openssl req -x509 -newkey rsa:4096 -out too_large_cert.der -outform DER -sha256 -days 3650 -nodes -subj '/C=01/ST=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/L=01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567/O=0123456789012345678901234567890123456789012345678901234567890123/OU=0123456789012345678901234567890123456789012345678901234567890123' > /dev/null 2>&1
        assert_success "Generating a large certificate"
    run "$pkcs11" --module "$MODULE" --login --pin 0001password --write-object too_large_cert.der --id 6464 --type cert
        assert_success "Import large x509 certificate"
    run "$pkcs11" --module "$MODULE" --login --pin 0001password --read-object --id 6464 --type cert --output-file too_large_cert_out.der
        assert_success "Get imported certificate"
    run cmp too_large_cert.der too_large_cert_out.der
        assert_success "Compare read certificate with the one imported"
    run "$pkcs11" --module "$MODULE" --login --pin 0001password --delete-object --id 6464 --type cert
        assert_success "Delete certificate"
    run rm too_large_cert.der too_large_cert_out.der privkey.pem
        assert_success "Delete files"
}
