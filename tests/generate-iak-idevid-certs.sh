#!/bin/bash

# Generate a test root CA and intermediate CA keys and certificates
# Then, generate IAK and IDevID keys inside the TPM and certificates signed by
# the interemediate CA

GIT_ROOT=$(git rev-parse --show-toplevel) || {
    echo "Please run this script from inside the rust-keylime repository tree"
    exit 1
}

TESTS_DIR=${GIT_ROOT}/tests
GIT_CA_CONF=${TESTS_DIR}/ca.conf
CA_PWORD=keylime

# It is expected that the TCTI and TPM2TOOLS_TCTI environment variables are set
# before running the script

if [[ -z "$TCTI" ]]; then
    echo "TCTI environment variable not set; using default /dev/tpmrm0"
    TCTI=device:/dev/tpmrm0
fi

if [[ -z "$TPM2TOOLS_TCTI" ]]; then
    echo "TPM2TOOLS_TCTI environment variable not set; using default /dev/tpmrm0"
    TPM2TOOLS_TCTI=device:/dev/tpmrm0
fi

if [[ -z "$TPM2OPENSSL_TCTI" ]]; then
    echo "TPM2OPENSSL_TCTI environment variable not set; using default /dev/tpmrm0"
    TPM2OPENSSL_TCTI=device:/dev/tpmrm0
fi

# Check that tpm2-openssl provider is available
if ! openssl list -provider tpm2 -providers; then
    echo "Please install the tpm2-openssl provider"
    exit 1
fi

function usage {
    echo "Usage: $0 [--output OUTPUT_DIR][--pwd CA_PASSWORD]"
    exit 0
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -o|--output)
      shift
      if [[ $# -gt 0 ]]; then
          OUTPUTDIR="$1"
          shift
      else
          echo "Missing path to output directory"
          usage
      fi
      ;;
    -p|--pwd)
      shift
      if [[ $# -gt 0 ]]; then
          CA_PWORD="$1"
          shift
      else
          echo "Missing password"
          usage
      fi
      ;;
    *)
      # Ignore unknown options
      shift
      ;;
  esac
done

# If the output directory is not set, create a temporary directory to output the
# certificates
if [[ -z "$OUTPUTDIR" ]]; then
    TEMPDIR=$(mktemp -d)
    OUTPUTDIR="${TEMPDIR}/certs"
    mkdir -p "${OUTPUTDIR}"
fi

echo "Writing the certificates to the directory ${OUTPUTDIR}"

# Generate IAK/IDevID CA certificates
mkdir -p "${OUTPUTDIR}/root"

# Copy CA configuration to output directory
CA_CONF=${OUTPUTDIR}/ca.conf
cp "${GIT_CA_CONF}" "${OUTPUTDIR}/ca.conf"

ROOT_CA_DIR="${OUTPUTDIR}/root"
INTERMEDIATE_CA_DIR="${OUTPUTDIR}/intermediate"

# Replace the output directory path accordingly
sed -i "s|REPLACE_ROOT_CA_DIR|${ROOT_CA_DIR}|" "${CA_CONF}"
sed -i "s|REPLACE_INTERMEDIATE_CA_DIR|${INTERMEDIATE_CA_DIR}|" "${CA_CONF}"

pushd "${OUTPUTDIR}" > /dev/null || exit 1
    mkdir -p root root/crl root/certs
    pushd root > /dev/null || exit 1
        touch index.txt
        echo 1000 > serial

        # Create private key for root CA certificate
        openssl genrsa \
            -aes256 \
            -passout "pass:${CA_PWORD}" \
            -out private.pem 4096

        # Create self-signed root CA certificate
        openssl req \
            -config "${CA_CONF}" \
            -subj "/C=US/ST=MA/L=Lexington/O=Keylime Tests/CN=Keylime Test Root CA" \
            -key private.pem \
            -passin "pass:${CA_PWORD}" \
            -new \
            -x509 \
            -days 9999 \
            -sha384 \
            -extensions v3_ca \
            -out cacert.pem
    popd > /dev/null || exit 1

    # Create intermediate CA keys and certificate
    mkdir -p intermediate
    pushd intermediate > /dev/null || exit 1
        mkdir certs csr crl
        touch index.txt
        echo 1000 > serial

        # Create private keys for intermediary CA
        openssl genrsa \
            -aes256 \
            -passout "pass:${CA_PWORD}" \
            -out private.pem 4096

        # Create CSR for the intermediate CA
        openssl req \
            -config "${CA_CONF}" \
            -subj "/C=US/ST=MA/L=Lexington/O=Keylime Tests/CN=Keylime Test Intermediate CA" \
            -key private.pem \
            -passin "pass:${CA_PWORD}" \
            -new \
            -sha256 \
            -out csr/intermediate.csr.pem

        # Create certs and cert chain for the intermediate CA
        openssl ca \
            -config "${CA_CONF}" \
            -extensions v3_intermediate_ca \
            -keyfile "${ROOT_CA_DIR}/private.pem" \
            -cert "${ROOT_CA_DIR}/cacert.pem" \
            -days 9998 \
            -notext \
            -md sha384 \
            -batch \
            -in csr/intermediate.csr.pem \
            -passin "pass:${CA_PWORD}" \
            -out cacert.pem
    popd > /dev/null || exit 1
    cat intermediate/cacert.pem root/cacert.pem \
        > cert-chain.pem
popd > /dev/null || exit 1

mkdir "${OUTPUTDIR}/ikeys"
pushd "${OUTPUTDIR}/ikeys" > /dev/null || exit 1

    # The templates used in order to regenerate the IDevID and IAK keys are
    # taken from the TCG document "TPM 2.0 Keys for Device Identity and
    # Attestation:
    #
    # https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf
    #
    # The template H-1 is used here.
    #
    # The unique values piped in via xxd for the '-u -' parameter are 'IDevID' and
    # 'IAK' strings in hex, as defined in section 7.3.1
    #
    # The attributes (-a) and algorithms (-g, -G) are specified in 7.3.4.1 Table
    # 3 and 7.3.4.2 Table 4 respectively
    #
    # The policy values (-L) are specified in 7.3.6.6 Table 19

    # Regenerate IDevID within TPM
    echo -n 494445564944 | xxd -r -p | tpm2_createprimary -C e \
        -g sha256 \
        -G rsa2048:null:null \
        -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|adminwithpolicy|sign' \
        -L 'ad6b3a2284fd698a0710bf5cc1b9bdf15e2532e3f601fa4b93a6a8fa8de579ea' \
        -u - \
        -c idevid.ctx -o idevid.pub.pem

    # Persist IDevID and save handle index
    tpm2_evictcontrol -c idevid.ctx | grep -o '0x.*$' > idevid.handle

    # Create CSRs for the IDevID and sign with the intermediate CA
    openssl req \
        -config "${CA_CONF}" \
        -subj "/C=US/ST=MA/L=Lexington/O=Keylime Tests/CN=Keylime IDevID" \
        -provider tpm2 \
        -provider default \
        -propquery '?provider=tpm2' \
        -new \
        -key "handle:$(cat idevid.handle)" \
        -out "${INTERMEDIATE_CA_DIR}/csr/idevid.csr.pem"

    openssl ca \
        -config "${CA_CONF}" \
        -name CA_intermediate \
        -extensions server_cert \
        -days 999 \
        -notext \
        -passin "pass:${CA_PWORD}" \
        -batch -md sha384 \
        -in "${INTERMEDIATE_CA_DIR}/csr/idevid.csr.pem" \
        -out "${OUTPUTDIR}/idevid.cert.pem"

    # Evict the persisted IDevID key using the handle and cleanup any transient
    # object
    tpm2_evictcontrol -c "$(cat idevid.handle)"
    tpm2_flushcontext -t -l -s

    # Regenerate IAK within TPM
    echo -n 49414b | xxd -r -p | tpm2_createprimary -C e \
        -g sha256 \
        -G rsa2048:rsapss-sha256:null \
        -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|adminwithpolicy|sign|restricted' \
        -L '5437182326e414fca797d5f174615a1641f61255797c3a2b22c21d120b2d1e07' \
        -u - \
        -c iak.ctx -o iak.pub.pem

    # Persist IAK and save handle index
    tpm2_evictcontrol -c iak.ctx | grep -o '0x.*$' > iak.handle

    # Create CSRs for the IAK and sign with the intermediate CA
    openssl req \
        -config "${CA_CONF}" \
        -subj "/C=US/ST=MA/L=Lexington/O=Keylime Tests/CN=Keylime IAK" \
        -provider tpm2 \
        -provider default \
        -propquery '?provider=tpm2' \
        -new \
        -key "handle:$(cat iak.handle)" \
        -out "${INTERMEDIATE_CA_DIR}/csr/iak.csr.pem"

    openssl ca \
        -config "${CA_CONF}" \
        -name CA_intermediate \
        -extensions server_cert -days 999 \
        -notext \
        -passin "pass:${CA_PWORD}" \
        -batch \
        -md sha384 \
        -in "${INTERMEDIATE_CA_DIR}/csr/iak.csr.pem" \
        -out "${OUTPUTDIR}/iak.cert.pem"

    # Evict the persisted IAK key using the handle and cleanup any transient
    # object
    tpm2_evictcontrol -c "$(cat iak.handle)"
    tpm2_flushcontext -t -l -s

    # Convert certs to DER
    openssl x509 \
        -inform PEM \
        -outform DER \
        -in "${OUTPUTDIR}/idevid.cert.pem" \
        -out "${OUTPUTDIR}/idevid.cert.der"

    openssl x509 \
        -inform PEM \
        -outform DER \
        -in "${OUTPUTDIR}/iak.cert.pem" \
        -out "${OUTPUTDIR}/iak.cert.der"
popd > /dev/null || exit 1

