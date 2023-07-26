<?php

namespace Worldxyj;

class Jwt
{
    /**
     * 头部
     * @var string[]
     */
    private static $header = [
        'alg' => 'HS256',   //生成signature的算法
        'typ' => 'JWT'      //类型
    ];

    /**
     * 使用 HMAC 生成信息摘要时所使用的密钥
     * 生产环境请修改秘钥
     * @var string
     */
    public $secret;

    /**
     * 义在什么时间之前，该jwt都是不可用的
     * @var int
     */
    public $nbf;

    /**
     * jwt签发者
     * @var string
     */
    public $iss;

    /**
     * jwt所面向的用户
     * @var string
     */
    public $sub;

    public function __construct($secret = 'secret', $nbf = 0, $iss = '', $sub = '' )
    {
        $this->secret = $secret;
        $this->nbf = $nbf;
        $this->iss = $iss;
        $this->sub = $sub;
    }

    /**
     * 获取jwt token
     * 默认过期时间1天
     *
     * @param array $payload jwt载荷
     * @return array
     */
    public function getToken($payload)
    {
        $arr = [
            'iss' => $this->iss, //该JWT的签发者
            'iat' => time(), //签发时间
            'exp' => time() + 3600 * 24, //过期时间
            'nbf' => $this->nbf, //定义在什么时间之前，该jwt都是不可用的
            'sub' => $this->sub, //面向的用户
            'jti' => md5(uniqid('JWT') . time()) //该Token唯一标识
        ];
        $payload = array_merge($arr, $payload);
        if (is_array($payload)) {
            $base64header = self::base64UrlEncode(json_encode(self::$header, JSON_UNESCAPED_UNICODE));
            $base64payload = self::base64UrlEncode(json_encode($payload, JSON_UNESCAPED_UNICODE));
            $token = $base64header . '.' . $base64payload . '.' . $this->signature($base64header . '.' . $base64payload, $this->secret, self::$header['alg']);
            return $this->responseSuccess($token);
        } else {
            return $this->responseError(106, 'payload格式错误');
        }
    }

    /**
     * 获取jwt token
     * 自定义过期时间
     *
     * @param array $payload
     * @param int $exp
     * @return array
     *
     */
    public function getTokenWithExp($payload, $exp)
    {
        $arr = [
            'iss' => $this->iss, //该JWT的签发者
            'iat' => time(), //签发时间
            'exp' => time() + (int)$exp, //过期时间
            'nbf' => $this->nbf, //该时间之前不接收处理该Token
            'sub' => $this->sub, //面向的用户
            'jti' => md5(uniqid('JWT') . time()) //该Token唯一标识
        ];
        $payload = array_merge($arr, $payload);
        if (is_array($payload)) {
            $base64header = self::base64UrlEncode(json_encode(self::$header, JSON_UNESCAPED_UNICODE));
            $base64payload = self::base64UrlEncode(json_encode($payload, JSON_UNESCAPED_UNICODE));
            $token = $base64header . '.' . $base64payload . '.' . $this->signature($base64header . '.' . $base64payload, $this->secret, self::$header['alg']);
            return $this->responseSuccess($token);
        } else {
            return $this->responseError(106, 'payload格式错误');
        }
    }

    /**
     * 验证token是否有效,默认验证exp,nbf,iat时间
     *
     * @param string $Token 需要验证的token
     * @return array
     */
    public function verifyToken($Token)
    {
        $tokens = explode('.', $Token);
        if (count($tokens) != 3){
            return $this->responseError(101, 'token格式错误');
        }

        list($base64header, $base64payload, $sign) = $tokens;

        //获取jwt算法
        $base64decodeheader = json_decode(self::base64UrlDecode($base64header), JSON_OBJECT_AS_ARRAY);
        if (empty($base64decodeheader['alg'])){
            return $this->responseError(102, 'alg错误');
        }

        //签名验证
        if ($this->signature($base64header . '.' . $base64payload, $this->secret, $base64decodeheader['alg']) !== $sign){
            return $this->responseError(100, '签名验证失败');
        }

        $payload = json_decode(self::base64UrlDecode($base64payload), JSON_OBJECT_AS_ARRAY);

        //签发时间大于当前服务器时间验证失败
        if (isset($payload['iat']) && $payload['iat'] > time()){
            return $this->responseError(103, '签发时间大于当前服务器时间');
        }

        //过期时间小宇当前服务器时间验证失败
        if (isset($payload['exp']) && $payload['exp'] < time()){
            return $this->responseError(104, 'token已过期');
        }

        //定义在什么时间之前，该jwt都是不可用的
        if (isset($payload['nbf']) && $payload['nbf'] > time()){
            return $this->responseError(105, '未到生效时间');
        }

        return $this->responseSuccess($payload);
    }

    /**
     * base64UrlEncode
     * https://jwt.io/ 中base64UrlEncode编码实现
     *
     * @param string $input 需要编码的字符串
     * @return string
     */
    private static function base64UrlEncode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * base64UrlEncode
     * https://jwt.io/ 中base64UrlEncode解码实现
     *
     * @param string $input 需要解码的字符串
     * @return bool|string
     */
    private static function base64UrlDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * HMACSHA256签名
     * https://jwt.io/ 中HMACSHA256签名实现
     *
     * @param string $input 为base64UrlEncode(header).".".base64UrlEncode(payload)
     * @param string $key
     * @param string $alg 算法方式
     * @return mixed
     */
    private function signature($input)
    {
        $hash = hash_hmac('sha256', $input, $this->secret, true);
        return self::base64UrlEncode($hash);
    }

    /**
     * 验证成功
     *
     * @param $playload
     * @return array
     */
    protected function responseSuccess($playload)
    {
        return [
            'errcode' => 0,
            'msg' => '',
            'data' => $playload,
        ];
    }

    /**
     * 验证失败
     *
     * @param $errcode
     * @param $msg
     * @return array
     */
    protected function responseError($errcode, $msg)
    {
        return [
            'errcode' => $errcode,
            'msg' => $msg,
            'data' => [],
        ];
    }
}