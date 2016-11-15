<?php
namespace Cigital\Safetynet;

/**
 * Class PayloadValidator
 *
 * @package Cigital\Safetynet
 */
class PayloadValidator
{
    /** @var string $payload_error_msg */
    public $payload_error_msg = array();
    /** @var string $expected_package_name */
    protected $expected_package_name;
    /** @var string $expected_apk_cert_digest */
    protected $expected_apk_cert_digest;
    /** @var string $expected_apk_digest */
    protected $expected_apk_digest;

    /** @var Session $session */
    protected $session;

    /**
     * PayloadValidator constructor.
     *
     * @param Session $session
     * @param string  $expected_package_name
     * @param string  $expected_apk_cert_digest
     * @param string  $expected_apk_digest
     */
    public function __construct(Session $session, $expected_package_name, $expected_apk_cert_digest, $expected_apk_digest)
    {
        $this->session = $session;
        $this->expected_package_name = $expected_package_name;
        $this->expected_apk_cert_digest = $expected_apk_cert_digest;
        $this->expected_apk_digest = $expected_apk_digest;
    }

    /**
     * @return string
     */
    public function getExpectedPackageName()
    {
        return $this->expected_package_name;
    }

    /**
     * @return string
     */
    public function getExpectedApkCertDigest()
    {
        return $this->expected_apk_cert_digest;
    }

    /**
     * @return string
     */
    public function getExpectedApkDigest()
    {
        return $this->expected_apk_digest;
    }

    /**
     * @param array $payload todo: make this an object to avoid relying on dynamic arrays
     *
     * @return bool
     */
    public function validate($payload)
    {
        $validation_array = [
            "isNonceValid"         => $this->validateNonce($payload['nonce']),
            "isTimestampValid"     => $this->validateTimestamp($payload['timestampMs']),
            "isPackageNameValid"   => $this->validateAPKpackageName($payload['apkPackageName']),
            "isAPKcertDigestValid" => $this->validateAPKcertDigest($payload['apkCertificateDigestSha256']),
            "isAPKpathDigestValid" => $this->validateAPKDigest($payload['apkDigestSha256']),
            "ctsProfileMatch"      => $this->validateCtsProfileMatch($payload['ctsProfileMatch']),
            "basicIntegrity"       => $this->validateBasicIntegrity($payload['basicIntegrity']),
        ];

        // If all items in the validation array are True, return True.
        // There's probably a better way to do this.

        if (count(array_unique($validation_array)) === 1) {
            return current($validation_array);
        } else {
            return false;
        }
    }

    /**
     * Validate if the nonce inside the JWS payload is the last one we sent to the app instance requesting it
     *
     * @param string $received_nonce
     *
     * @return bool
     */
    protected function validateNonce($received_nonce)
    {
        $nonce = $this->session->get('nonce');
        if (strcmp(base64_decode($nonce), base64_decode($received_nonce, true)) === 0) {
            return true;
        } else {
            $this->payload_error_msg[] = "Invalid nonce";
            return false;
        }

    }

    /**
     * Validate if the timestamp inside the JWS payload is within 1000ms since we generated the last nonce.
     * This limit may need to be reviewed.
     *
     * @param $received_timestampMs
     *
     * @return bool
     */
    protected function validateTimestamp($received_timestampMs)
    {

        $received = $received_timestampMs / 1000;
        $noncetime = $this->session->get('nonce_timestamp');
        $difference = $received - $noncetime;

        if (($difference < 1000) && ($difference > 0)) {
            return true;
        } else {
            $this->payload_error_msg[] = "Invalid timestamp";
            return false;
        }
    }

    /**
     * Validate if the package name of the app requesting the attest result matches the package name of our app
     *
     * @param $received_apkPackageName
     *
     * @return bool
     */
    protected function validateAPKpackageName($received_apkPackageName)
    {
        if (strcmp($this->expected_package_name, $received_apkPackageName) === 0) {
            return true;
        } else {
            $this->payload_error_msg[] = "Invalid package name";
            return false;
        }
    }

    /**
     * Validate if the hash of the leaf certificate name of the app requesting the attest result matches our app
     *
     * @param $received_apkCertificateDigestSha256
     *
     * @return bool
     */
    protected function validateAPKcertDigest($received_apkCertificateDigestSha256)
    {
        $decoded_apk_cert_digest = bin2hex(base64_decode($received_apkCertificateDigestSha256[0]));
        if (strcasecmp(
                $this->expected_apk_cert_digest,
                $decoded_apk_cert_digest
            ) === 0
        ) {
            return true;
        } else {
            $this->payload_error_msg[] = "Invalid APK certificate digest";
            return false;
        }
    }

    /**
     * Validate if the hash of the apk of the app requesting the attest result matches our app
     *
     * @param $received_apkDigestSha256
     *
     * @return bool
     */
    protected function validateAPKDigest($received_apkDigestSha256)
    {
        $decoded_apkDigestSha256 = bin2hex(base64_decode($received_apkDigestSha256));
        if (strcasecmp($this->expected_apk_digest, $decoded_apkDigestSha256) === 0) {
            return true;
        } else {
            $this->payload_error_msg[] = "Invalid APK binary digest";
            return false;
        }
    }

    /**
     * Return the result of the ctsCompatibility check
     *
     * @param $received_ctsProfileMatch
     *
     * @return bool
     */
    protected function validateCtsProfileMatch($received_ctsProfileMatch)
    {
        if($received_ctsProfileMatch === true){
            return true;
        }
        else{
            $this->payload_error_msg[] = "ctsProfileMatch is false";
            return false;
        }
    }

    /**
     * Return the result of the basicIntegrity check
     *
     * @param $received_basicIntegrity
     *
     * @return bool
     */
    protected function validateBasicIntegrity($received_basicIntegrity)
    {
        if($received_basicIntegrity === true){
            return true;
        }
        else{
            $this->payload_error_msg[] = "basicIntegrity is false";
            return false;
        }
    }
}
