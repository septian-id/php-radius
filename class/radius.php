<?php
namespace server;
class RadiusServer
{
    public $radius_codes = [
        1 => "Access-Request",
        2 => "Access-Accept",
        3 => "Access-Reject",
        4 => "Accounting-Request",
        5 => "Accounting-Response",
        11 => "Access-Challenge",
        12 => "Status-Server",
        13 => "Status-Client",
    ];
    public $radius_acc_atributes = [
        40 => "Acct-Status-Type",
        41 => "Acct-Delay-Time",
        42 => "Acct-Input-Octets",
        43 => "Acct-Output-Octets",
        44 => "Acct-Session-Id",
        45 => "Acct-Authentic",
        46 => "Acct-Session-Time",
        47 => "Acct-Input-Packets",
        48 => "Acct-Output-Packets",
        49 => "Acct-Terminate-Cause",
        50 => "Acct-Multi-Session-Id",
        51 => "Acct-Link-Count",
    ];
    public $radius_attributes = [
        1 => "User-Name",
        2 => "User-Password",
        3 => "CHAP-Password",
        4 => "NAS-IP-Address",
        5 => "NAS-Port",
        6 => "Service-Type",
        7 => "Framed-Protocol",
        8 => "Framed-IP-Address",
        9 => "Framed-IP-Netmask",
        10 => "Framed-Routing",
        11 => "Filter-ID",
        12 => "Framed-MTU",
        13 => "Framed-Compression",
        14 => "Login-IP-Host",
        15 => "Login-Service",
        16 => "Login-TCP-Port",
        18 => "Reply-Message",
        19 => "Callback-Number",
        20 => "Callback-Id",
        24 => "State",
        25 => "Class",
        26 => "Vendor-Specific",
        27 => "Session-Timeout",
        28 => "Idle-Timeout",
        29 => "Termination-Action",
        30 => "Called-Station-Id",
        31 => "Calling-Station-Id",
        32 => "NAS-Identifier",
        33 => "Proxy-State",
        34 => "Login-LAT-Service",
        35 => "Login-LAT-Node 3",
        36 => "Login-LAT-Group",
        37 => "Framed-AppleTalk-Link",
        38 => "Framed-AppleTalk-Network",
        39 => "Framed-AppleTalk-Zone",
        60 => "CHAP-Challenge",
        61 => "NAS-Port-Type",
        62 => "Port-Limit",
        63 => "Login-LAT-Port",
        79 => "EAP-Message",
        80 => "Message-Authenticator",
        87 => "NAS-Port-ID",
    ];
    public $radiusAttributesReverse = [];
    public $vendorRadiusAttributes = [];
    public $vendorRadiusAttributesReverse = [];
    public $radiusCodesReverse = [];
    private $socket;
    private $peer;
    private $receive_buffer = 65535;
    private $serverip = "0.0.0.0";
    private $serverport = 1812;
    private $secret = "secret";
    private $time = 0;
    private $requests = 0;
    private $requests_min = 0;
    private $requests_max = 0;
    public $debugLevel = RADIUS_BASIC; // 0=off, 1=basic, 2=connection, 3=info, 4=debug
    private $log_file = false; // where to save logs
    private $authMethod = null;
    private $authClass = null;
    protected $loginInfo;

    public function __construct()
    {
        if (PHP_MAJOR_VERSION < 7) {
            $this->log(
                "Please consider updating to PHP7, as you will get 4x better performance",
                RADIUS_BASIC
            );
        }

        if (!function_exists("socket_create")) {
            die(
                "Please include socket extension (php_sockets.dll or php_sockets.so)"
            );
        }
    }

    public function initialize($serverip = false, $serverport = false)
    {
        if ($serverip) {
            $this->serverip = $serverip;
            $this->serverport = $serverport;
        }

        $this->log(
            "Running RADIUS server {$this->serverip} : {$this->serverport} on PHP " .
                PHP_VERSION .
                "",
            RADIUS_BASIC
        );

        if (!($this->socket = socket_create(AF_INET, SOCK_DGRAM, 0))) {
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);

            die("Couldn't create socket: [$errorcode] $errormsg \n");
        }

        if (!socket_bind($this->socket, $this->serverip, $this->serverport)) {
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);

            die("Could not bind socket : [$errorcode] $errormsg \n");
        }
    }

    protected function log($message, $debug = null)
    {
        if ($debug === null || $this->debugLevel >= $debug) {
            if ($this->log_file) {
                $r = file_put_contents($this->log_file, $message, FILE_APPEND);
                if ($r === false) {
                    echo "ERROR: Could not write to log!\n";
                }
            } else {
                echo $message . "\n";
            }
        }
    }

    private function inverseAttributes($attrs)
    {
        foreach ($attrs as $id => $val) {
            $this->vendorRadiusAttributesReverse[$id] = $val;
        }
    }

    private function setup_attributes($vendor_radius_attributes)
    {
        foreach ($this->vendorRadiusAttributes as $attr => $vars) {
            if (isset($vars["id"])) {
                $this->vendorRadiusAttributesReverse[$vars["id"]] = $vars;
                continue;
            }
            if (is_array($vars)) {
                $this->inverseAttributes($vars);
                continue;
            }
        }
        if (DEBUG) {
            file_put_contents(
                __DIR__ . "/../json/dump_attrs.json",
                json_encode($this->vendorRadiusAttributesReverse),
                FILE_APPEND
            );
        }
    }

    public function reverse_dictionary()
    {
        $this->radiusAttributesReverse = array_flip($this->radius_attributes);
        $this->radiusCodesReverse = array_flip($this->radius_codes);
        $this->setup_attributes($this->vendorRadiusAttributes);
    }

    public function load_dictionary($file = "dictionary")
    {
        $dictionaryPath =
            RADIUS_SERVER_BASE .
            DIRECTORY_SEPARATOR .
            "dictionary" .
            DIRECTORY_SEPARATOR .
            $file;
        if (file_exists($dictionaryPath)) {
            $this->log("Load " . $file, RADIUS_BASIC);
            $dict = file_get_contents(
                RADIUS_SERVER_BASE . "/dictionary/" . $file
            );
            $dict_lines = explode("\n", $dict);
            $current_vendor = null;
            foreach ($dict_lines as $dict_item) {
                if (strlen($dict_item) < 10 || $dict_item[0] == "#") {
                    continue;
                } elseif (substr($dict_item, 0, 8) == "\$INCLUDE") {
                    $dict_file = trim(substr($dict_item, 9));
                    $this->load_dictionary($dict_file);
                } else {
                    $dict_item = str_replace(chr(9), " ", $dict_item);
                    while (strpos($dict_item, "  ")) {
                        $dict_item = str_replace("  ", " ", $dict_item);
                    }
                    $dict_item_e = explode(" ", $dict_item);
                    switch ($dict_item_e[0]) {
                        case "VENDOR":
                            $this->vendorRadiusAttributes[$dict_item_e[1]][
                                "id"
                            ] = $dict_item_e[2];
                            break;
                        case "BEGIN-VENDOR":
                            $current_vendor = $dict_item_e[1];
                            break;
                        case "END-VENDOR":
                            $current_vendor = null;
                            break;
                        case "ATTRIBUTE":
                            if (!$current_vendor) {
                                $this->radius_attributes[$dict_item_e[2]] =
                                    $dict_item_e[1];
                            } else {
                                $this->vendorRadiusAttributes[$current_vendor][
                                    $dict_item_e[1]
                                ] = $dict_item_e[2];
                            }
                            break;
                        case "VALUE":
                            break;
                        default:
                    }
                }
            }
            return true;
        } else {
            $this->log("Failed to load " . $file, RADIUS_BASIC);
            return false;
        }
    }

    private function hex_dump($string)
    {
        $hex = "";
        for ($c = 0; $c < strlen($string); $c++) {
            $hexnum = dechex(ord($string[$c]));
            if (strlen($hexnum) < 2) {
                $hexnum = "0" . $hexnum;
            }
            $hex .= $hexnum;
        }
        return $hex;
    }

    private function debug_hex_dump($content, $filename = false)
    {
        $hex = $this->hex_dump($content);
        if ($filename) {
            file_put_contents(__DIR__ . "/" . $filename, $hex);
        } else {
            $this->log($hex, RADIUS_DEBUG);
        }
    }

    private function create_user_password($password, $auth, $secret)
    {
        if (strlen($password) == 0) {
            return false;
        }
        if (strlen($password) > 16) {
            $password_pack = substr($password, 0, 16);
        } elseif (strlen($password) < 16) {
            $password_pack = str_pad($password, 16, chr(0x00));
            $password_pack_hex = $this->hex_dump($password_pack);
        } else {
            $password_pack = $password;
        }

        $phash = md5($secret . $auth);

        $enc = "";
        for ($c = 0; $c < 32; $c = $c + 2) {
            $xor =
                hexdec($phash[$c] . $phash[$c + 1]) ^
                hexdec($password_pack_hex[$c] . $password_pack_hex[$c + 1]);
            $xorh = dechex($xor);
            if (strlen($xorh) < 2) {
                $xorh = "0" . $xorh;
            }
            $enc .= $xorh;
        }
        return $enc;
    }

    public function loginCheck($username)
    {
        if (!$this->authClass) {
            $authClass = "\\auth\\$this->authMethod";
            $this->authClass = new $authClass();
        }
        $this->loginInfo = $this->authClass->getLoginInfo($username);
        if ($this->loginInfo === false) {
            return false;
        }
        if(isset($this->loginInfo['password'])){
            return $this->loginInfo["password"];
        }
    }

    private function loginMatch($auth, $attr)
    {
        $password = $this->loginCheck($attr["User-Name"]["value"]);
        if (!$password) {
            $this->log(
                "The username or password for ---> " . $attr["User-Name"]["value"],
                RADIUS_DEBUG
            );
            return false;
        }
        if (@$attr["CHAP-Challenge"]) {
            // https://tools.ietf.org/html/rfc2058#section-5.40
            $chapID = $attr["CHAP-Password"]["value"][0];
            $encrypted_password = md5(
                $chapID . $password . $attr["CHAP-Challenge"]["value"]
            );
            $requested_password = $this->hex_dump(
                substr($attr["CHAP-Password"]["value"], 1)
            );
            return $requested_password == $encrypted_password;
        } elseif (@$attr["CHAP-Password"]) {
            // https://tools.ietf.org/html/rfc2058#section-5.3
            $chapID = $attr["CHAP-Password"]["value"][0];
            $encrypted_password = md5($chapID . $password . $auth);
            $requested_password = $this->hex_dump(
                substr($attr["CHAP-Password"]["value"], 1)
            );
            return $requested_password == $encrypted_password;
        } elseif (@$attr["EAP-Message"]) {
            die("EAP unsupported.");
        } elseif (@$attr["User-Password"]) {
            // https://tools.ietf.org/html/rfc2058#section-5.2
            $encrypted_password = $this->create_user_password(
                $password,
                $auth,
                $this->secret
            );
            $requested_password = $this->hex_dump(
                $attr["User-Password"]["value"]
            );
            return $requested_password == $encrypted_password;
        } elseif (@$attr["MS-CHAP-Challenge"]) {
            die("MS-CHAP unsupported.");
        } else {
            die("Missing password.");
        }
        return false;
    }

    public function set_attribute($attribute, $value)
    {
        $this->log("   {$attribute} -> {$value}", RADIUS_INFO);
        switch ($attribute) {
            case "Framed-IP-Address":
                $value = $this->encode_ip($value);
            default:
        }
        $code = @$this->radiusAttributesReverse[$attribute];
        if (!$code) {
            $this->log(
                "Radius Attribute [$attribute] Tidak Dikenali",
                RADIUS_INFO
            );
            return false;
        }

        $packed = pack(
            "CCa" . strlen($value),
            $code,
            strlen($value) + 2,
            $value
        );
        return $packed;
    }

    public function decode_attr($code, $request, $size)
    {
        $csize = 0;
        while ($csize < $size) {
            if ($code == $this->radiusCodesReverse["Access-Request"]) {
                $type = $this->radius_attributes[ord($request[$csize])];
            } elseif (
                $code == $this->radiusCodesReverse["Accounting-Request"]
            ) {
                $type = $this->radius_acc_atributes[ord($request[$csize])];
            } else {
                $this->log("Unknown packet type {$code}", RADIUS_BASIC);
            }

            $len = ord($request[$csize + 1]);
            $value = substr($request, $csize + 2, $len - 2);
            $array_value = [];
            for ($c = 0; $c < strlen($value); $c++) {
                $array_value[] = ord($value[$c]);
            }
            $attr[$type] = [
                "value" => $value,
                "array_value" => $array_value,
            ];
            $csize += $len;
            if (RADIUS_INFO == $this->debugLevel) {
                $value = $this->hex_dump($value);
            }
            $this->log("   {$type} => {$value}", RADIUS_INFO);
        }
        return $attr;
    }

    public function encode_ip($ip)
    {
        $ip_parts = explode(".", $ip);
        $ip_packed = pack(
            "CCCC",
            $ip_parts[0],
            $ip_parts[1],
            $ip_parts[2],
            $ip_parts[3]
        );
        return $ip_packed;
    }

    private function process_code(
        $pkta,
        $pkt,
        $auth,
        $attr,
        $remote_ip,
        $remote_port
    ) {
        switch ($pkta["code"]) {
            case $this->radiusCodesReverse["Access-Request"]:
                $password_match = $this->loginMatch($auth, $attr);
                if ($password_match) {
                    $this->log("Reply: Access-Accept", RADIUS_INFO);
                    $reply = "";
                    foreach ($this->loginInfo as $attr => $val) {
                        if ($attr == "password") {
                            continue;
                        }
                        $reply .= $this->set_attribute($attr, $val);
                    }
                    $response_code = $this->radiusCodesReverse["Access-Accept"];
                    $response_length = 3 + 16 + 1 + strlen($reply);
                    $response_string = pack(
                        "CCna16a" .
                            strlen($reply) .
                            "a" .
                            strlen($this->secret),
                        $response_code,
                        $pkta["id"],
                        $response_length,
                        $auth,
                        $reply,
                        $this->secret
                    );
                    $response_auth = md5($response_string, true);
                    $response_string_binary = pack(
                        "CCna16a" . strlen($reply),
                        $response_code,
                        $pkta["id"],
                        $response_length,
                        $response_auth,
                        $reply
                    );
                    $this->radius_reply(
                        $response_string_binary,
                        $remote_ip,
                        $remote_port
                    );
                } else {
                    $this->log("Reply: Access-Reject", RADIUS_INFO);
                    $response_code = $this->radiusCodesReverse["Access-Reject"];
                    $response_length = 3 + 16 + 1;
                    $response_string = pack(
                        "CCna16a" . strlen($this->secret),
                        $response_code,
                        $pkta["id"],
                        $response_length,
                        $auth,
                        $this->secret
                    );
                    $response_auth = md5($response_string, true);
                    $response_string_binary = pack(
                        "CCna16",
                        $response_code,
                        $pkta["id"],
                        $response_length,
                        $response_auth
                    );
                    $this->radius_reply(
                        $response_string_binary,
                        $remote_ip,
                        $remote_port
                    );
                }
                break;
            case $this->radiusCodesReverse["Accounting-Request"]:
                $this->log("Reply: Accounting-Request", RADIUS_INFO);
                break;
            default:
        }
    }

    final public function process_request($pkt, $remote_ip, $remote_port)
    {
        $pkta = [
            "code" => ord($pkt[0]),
            "id" => ord($pkt[1]),
            "len" => ord($pkt[2]) * 255 + ord($pkt[3]),
        ];

        $this->log(
            "Request: {$this->peer} {$this->radius_codes[$pkta["code"]]} id  {$pkta["id"]} len {$pkta["len"]}",
            RADIUS_CONNECTION
        );

        if (strlen($pkt) < 21) {
            $this->log(
                "Packet less than 21, probalby empty request",
                RADIUS_INFO
            );
            return false;
        }

        $auth = substr($pkt, 4, 16);
        $avps = substr($pkt, 20);
        $attr = $this->decode_attr($pkta["code"], $avps, $pkta["len"] - 20);
        $this->log("Reply: ", RADIUS_INFO);
        $this->process_code(
            $pkta,
            $pkt,
            $auth,
            $attr,
            $remote_ip,
            $remote_port
        );

        return true;
    }

    private function parseConfig(array $config)
    {
        $this->receive_buffer = (int) $config["receive_buffer"];
        $this->serverip = $config["serverip"];
        $this->serverport = $config["serverport"];
        $this->secret = $config["secret"];
        $this->authMethod = $config["auth_method"];
    }

    public function radius_run(array $config)
    {
        $this->parseConfig($config);
        do {
            if ($this->time == 0) {
                $this->time = microtime(true);
                $last_requests = 0;
            }

            $this->log("Waiting for packet", RADIUS_CONNECTION);
            $pkta = [];
            $r = socket_recvfrom(
                $this->socket,
                $pkt,
                $this->receive_buffer,
                0,
                $remote_ip,
                $remote_port
            );

            $this->requests++;

            if (strlen($pkt) < 4) {
                $this->log(
                    "Malformed packet, reply size less than 4!",
                    RADIUS_INFO
                );
                continue;
            }
            $microtime = microtime(true);
            $elapsed = $microtime - $this->time;
            if ($elapsed > 1) {
                $req = $this->requests - $last_requests;
                if ($req < $this->requests_min || $this->requests_min < 1) {
                    $this->requests_min = $req;
                }
                if ($req > $this->requests_max) {
                    $this->requests_max = $req;
                }
                $this->log(
                    "Requests: {$req}/sec minimum {$this->requests_min} maximum {$this->requests_max}",
                    RADIUS_BASIC
                );
                $last_requests = $this->requests;
                $this->time = $microtime;
            }

            $this->process_request($pkt, $remote_ip, $remote_port);
        } while ($pkt !== false);
    }
    private function radius_reply($reply, $remote_ip, $remote_port)
    {
        socket_sendto(
            $this->socket,
            $reply,
            strlen($reply),
            0,
            $remote_ip,
            $remote_port
        );
    }
}
