<?php
namespace Cigital\Safetynet;

class JwsPayloadValidator
{
    /** @var string $raw_jws */
    protected $raw_jws;
    /** @var string $header */
    protected $header;
    /** @var string $payload */
    protected $payload;
    /** @var string $signature */
    protected $signature;

    /** @var Noncer $noncer */
    protected $noncer;

    /** @var PayloadValidator $payload_validator */
    protected $payload_validator;

    /** @var string $api_key */
    protected $api_key;

    /** @var bool $isValid */
    public $isValid;

    /** @var string $error_msg */
    public $error_msg = array();

    /**
     * JwsPayloadValidator constructor.
     *
     * @param PayloadValidator $validator
     * @param string           $api_key
     * @param string           $raw_json
     */
    public function __construct(PayloadValidator $validator, $api_key, $raw_json)
    {
        $this->payload_validator = $validator;
        $this->api_key = $api_key;

        // Split by "."
        $this->raw_jws = $raw_json;
        $jws_parts = explode(".", $raw_json);
        // Decode each part - in a real app you will want to decode it into an object
        if (count($jws_parts) === 3) {
            $this->header = json_decode(base64_decode($jws_parts[0]), true);
            $this->payload = json_decode(base64_decode($jws_parts[1]), true);
            $this->signature = json_decode(base64_decode($jws_parts[2]), true);
        }
        $this->isValid = $this->validate();
    }

    /**
     * Validate JWS signature and payload
     *
     * @return bool
     */
    public function validate()
    {
        if (!$this->validateSignatureWithGoogle()) {
            $this->error_msg = "Invalid JWS signature";
            return false;
        }

        if (!$this->payload_validator->validate($this->payload)) {
            $this->error_msg = $this->payload_validator->payload_error_msg;
            return false;
        }

        return true;
    }

    /**
     * Validate JWS signature using Google's Android Device Verification API
     *
     * @return bool
     */
    protected function validateSignatureWithGoogle()
    {
        $url = 'https://www.googleapis.com/androidcheck/v1/attestations/verify?key=' . $this->api_key;
        $data = array('signedAttestation' => $this->raw_jws);
        $json_data = json_encode($data);
        $options = array(
            'http' => array(
                'header'  => "Content-Type: application/json",
                'method'  => 'POST',
                'content' => $json_data,
            ),
        );
        $context = stream_context_create($options);
        $res = file_get_contents($url, false, $context);
        $result = json_decode($res, true);

        $isValidSignature = $result['isValidSignature'];

        return $isValidSignature;
    }
}
