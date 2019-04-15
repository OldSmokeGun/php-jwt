<?php
/**
 * Created by PhpStorm.
 * User: oldSmokeGun
 * Date: 2019/4/10
 * Time: 10:10
 */

namespace app\api\lib;

class Jwt
{
    /**
     * 密钥
     * @var
     */
    private $secret;

    /**
     * 校验错误信息
     * @var
     */
    private $validateErrorMsg;

    /**
     * token 类型
     * @var string
     */
    private $type = 'JWT';

    /**
     * 加密算法
     * @var string
     */
    private $alg = 'HS256';

    /**
     * 签发者
     * @var
     */
    private $iss;

    /**
     * 接收者
     * @var
     */
    private $acp;

    /**
     * 过期时间
     * @var
     */
    private $exp;

    /**
     * token 签发时间
     * @var
     */
    private $iat;

    /**
     * 私有声明部分
     * @var
     */
    private $pri = [];

    /**
     * 设置密钥
     * @param mixed $secret
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
        return $this;
    }

    /**
     * 设置 token 类型
     * @param $type
     * @return $this
     */
    public function setType($type)
    {
        $this->type = $type;
        return $this;
    }

    /**
     * 设置加密算法
     * @param $alg
     * @return $this
     */
    public function setAlg($alg)
    {
        $this->alg = $alg;
        return $this;
    }

    /**
     * 设置签发者
     * @param $iss
     * @return $this
     */
    public function setIss($iss)
    {
        $this->iss = $iss;
        return $this;
    }

    /**
     * 设置接收者
     * @param $acp
     * @return $this
     */
    public function setAcp($acp)
    {
        $this->acp = $acp;
        return $this;
    }

    /**
     * 设置过期时间
     * @param $exp
     * @return $this
     */
    public function setExp($exp)
    {
        $this->exp = $exp;
        return $this;
    }

    /**
     * 设置签发时间
     * @param $iat
     * @return $this
     */
    public function setIat($iat)
    {
        $this->iat = $iat;
        return $this;
    }

    /**
     * 设置私有声明部分
     * @param $pri
     * @return $this
     */
    public function setPri($pri)
    {
        $this->pri = $pri;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * @return string
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * @return string
     */
    public function getAlg()
    {
        return $this->alg;
    }

    /**
     * @return mixed
     */
    public function getIss()
    {
        return $this->iss;
    }

    /**
     * @return mixed
     */
    public function getAcp()
    {
        return $this->acp;
    }

    /**
     * @return mixed
     */
    public function getExp()
    {
        return $this->exp;
    }

    /**
     * @return mixed
     */
    public function getIat()
    {
        return $this->iat;
    }

    /**
     * @return mixed
     */
    public function getPri()
    {
        return $this->pri;
    }

    /**
     * 设置校验失败信息
     * @param mixed $validateErrorMsg
     */
    public function setValidateErrorMsg($validateErrorMsg)
    {
        $this->validateErrorMsg = $validateErrorMsg;
    }

    /**
     * 获取校验失败信息
     * @return mixed
     */
    public function getValidateErrorMsg()
    {
        return $this->validateErrorMsg;
    }

    /**
     * 生成 JWT
     * @return string
     */
    public function build()
    {
        $header = [
            'type' => $this->type,
            'alg' => $this->alg
        ];

        $header = base64_encode(json_encode($header, JSON_UNESCAPED_UNICODE));

        $payload = [
            'iss' => $this->iss,
            'acp' => $this->acp,
            'exp' => $this->exp,
            'iat' => $this->iat,
            'pri' => $this->pri
        ];

        $payload = base64_encode(json_encode($payload, JSON_UNESCAPED_UNICODE));

        switch ( strtoupper($this->alg) )
        {
            case 'HS256' :
                $signature = hash_hmac('sha256', $header.'.'.$payload, $this->secret);
                break;
            default :
                throw new \Exception('unsupported algorithm');
        }

        $token = $header . '.' . $payload . '.' . $signature;

        return $token;
    }

    /**
     * 解析 JWT
     * @param $jwt
     * @return array
     * @throws \Exception
     */
    public function parse($jwt)
    {
        $jwt = explode('.',$jwt);

        if ( count($jwt) !== 3 ) throw new \Exception('parse error');

        list($header, $payload, $signature) = [base64_decode($jwt[0]), base64_decode($jwt[1]), $jwt[2]];

        list($header, $payload) = [json_decode($header, true), json_decode($payload, true)];

        return [
            'header' => $header,
            'payload' => $payload,
            'signature' => $signature
        ];
    }

    /**
     * 验证 JWT
     * @param $jwt
     * @param $secret
     * @return bool
     * @throws \Exception
     */
    public function validate($jwt, $secret)
    {
        $time = time();
        $parseJwt = $this->parse($jwt);

        if ( $time > $parseJwt['payload']['exp'] )
        {
            $this->setValidateErrorMsg('身份已过期');
            return false;
        }

        $validateHeader = base64_encode(json_encode($parseJwt['header'],JSON_UNESCAPED_UNICODE));
        $validatePayload = base64_encode(json_encode($parseJwt['payload'],JSON_UNESCAPED_UNICODE));

        $validateSignature = hash_hmac('sha256', $validateHeader.'.'.$validatePayload, $secret);

        if ( $validateSignature !== $parseJwt['signature'] )
        {
            $this->setValidateErrorMsg('身份已失效');
            return false;
        }

        return true;
    }

}
