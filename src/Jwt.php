<?php
/**
 * Created by PhpStorm.
 * User: oldSmokeGun
 * Date: 2019/4/10
 * Time: 10:10
 */

namespace oldSmokeGun\Jwt;


class Jwt
{
    /**
     * 加密密钥
     * @var null|string
     */
    private $secret;

    /**
     * token 类型
     * @var null|string
     */
    private $type = 'JWT';

    /**
     * 加密算法
     * @var null|string
     */
    private $alg = 'HS256';

    /**
     * 签发者
     * @var null|string
     */
    private $iss;

    /**
     * 主题
     * @var null|string
     */
    private $sub;

    /**
     * 面向用户
     * @var null|string
     */
    private $aud;

    /**
     * 过期时间（单位：秒）
     * @var null|int
     */
    private $exp;

    /**
     * token 生效时间
     * @var null|int
     */
    private $nbf;

    /**
     * 签发时间
     * @var null|int
     */
    private $iat;

    /**
     * 唯一标识
     * @var null|string
     */
    private $jti;

    /**
     * 额外数据
     * @var null|array
     */
    private $extraData = [];

    /**
     * @return null|string
     */
    public function getSecret(): ?string
    {
        return $this->secret;
    }

    /**
     * @param null|string $secret
     *
     * @return Jwt
     */
    public function setSecret(?string $secret): self
    {
        $this->secret = $secret;
        return $this;
    }

    /**
     * @return null|string
     */
    public function getType(): ?string
    {
        return $this->type;
    }

    /**
     * @param null|string $type
     *
     * @return Jwt
     */
    public function setType(?string $type): self
    {
        $this->type = $type;
        return $this;
    }

    /**
     * @return null|string
     */
    public function getAlg(): ?string
    {
        return $this->alg;
    }

    /**
     * @param null|string $alg
     *
     * @return Jwt
     */
    public function setAlg(?string $alg): self
    {
        $this->alg = $alg;
        return $this;
    }

    /**
     * @return null|string
     */
    public function getIss(): ?string
    {
        return $this->iss;
    }

    /**
     * @param null|string $iss
     *
     * @return Jwt
     */
    public function setIss(?string $iss): self
    {
        $this->iss = $iss;
        return $this;
    }

    /**
     * @return null|string
     */
    public function getSub(): ?string
    {
        return $this->sub;
    }

    /**
     * @param null|string $sub
     *
     * @return Jwt
     */
    public function setSub(?string $sub): self
    {
        $this->sub = $sub;
        return $this;
    }

    /**
     * @return null|string
     */
    public function getAud(): ?string
    {
        return $this->aud;
    }

    /**
     * @param null|string $aud
     *
     * @return Jwt
     */
    public function setAud(?string $aud): self
    {
        $this->aud = $aud;
        return $this;
    }

    /**
     * @return int|null
     */
    public function getExp(): ?int
    {
        return $this->exp;
    }

    /**
     * @param int|null $exp
     *
     * @return Jwt
     */
    public function setExp(?int $exp): self
    {
        $this->exp = $exp;
        return $this;
    }

    /**
     * @return int|null
     */
    public function getNbf(): ?int
    {
        return $this->nbf;
    }

    /**
     * @param int|null $nbf
     *
     * @return Jwt
     */
    public function setNbf(?int $nbf): self
    {
        $this->nbf = $nbf;
        return $this;
    }

    /**
     * @return int|null
     */
    public function getIat(): ?int
    {
        return $this->iat;
    }

    /**
     * @param int|null $iat
     *
     * @return Jwt
     */
    public function setIat(?int $iat): self
    {
        $this->iat = $iat;
        return $this;
    }

    /**
     * @return null|string
     */
    public function getJti(): ?string
    {
        return $this->jti;
    }

    /**
     * @param null|string $jti
     *
     * @return Jwt
     */
    public function setJti(?string $jti): self
    {
        $this->jti = $jti;
        return $this;
    }

    /**
     * @return array|null
     */
    public function getExtraData(): ?array
    {
        return $this->extraData;
    }

    /**
     * @param array|null $extraData
     *
     * @return Jwt
     */
    public function setExtraData(?array $extraData): self
    {
        $this->extraData = $extraData;
        return $this;
    }


    /**
     * 生成 JWT
     *
     * @return string
     * @throws Exception
     */
    public function build(): string
    {
        if ( !$this->getSecret() )
        {
            throw new Exception('secret must be set');
        }

        $currentTime = time();
        $jti         = md5(time().uniqid(true, true));

        $header = [
            'type' => $this->getType(),
            'alg'  => strtoupper($this->getAlg())
        ];

        $payload = [
            'iss'   => $this->getIss() ?? '',
            'sub'   => $this->getSub() ?? '',
            'aud'   => $this->getAud() ?? '',
            'exp'   => $this->getExp() ?? (int) ($currentTime + 86400 * 7),
            'nbf'   => $this->getNbf() ?? (int) ($currentTime + 60 * 5),
            'iat'   => $this->getIat() ?? $currentTime,
            'jti'   => $this->getJti() ?? $jti,
            'extra' => $this->getExtraData() ?? []
        ];

        $header  = base64_encode(json_encode($header, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        $payload = base64_encode(json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));

        switch ( strtoupper($this->getAlg()) )
        {
            case 'MD5' :

                $signature = md5($header . '.' . $payload . $this->getSecret());

                break;

            case 'HS256' :

                $signature = hash_hmac('sha256', $header . '.' . $payload, $this->getSecret());

                break;

            default :

                throw new Exception('Unsupported encryption algorithm');
        }

        $token = $header . '.' . $payload . '.' . $signature;

        return $token;
    }

    /**
     * 解析 JWT
     *
     * @param $jwt
     * @return array
     * @throws \Exception
     */
    public function parse(string $jwt): array
    {
        $jwt = explode('.', $jwt);

        if ( count($jwt) !== 3 )
        {
            throw new \Exception('parse error');
        }

        list($header, $payload, $signature) = [
            json_decode(base64_decode($jwt[0]), true),
            json_decode(base64_decode($jwt[1]), true),
            $jwt[2]
        ];

        return [
            'header'    => $header,
            'payload'   => $payload,
            'signature' => $signature
        ];
    }

    /**
     * 验证 jwt
     *
     * @param string $jwt
     *
     * @return int 0 成功 1 签名验证错误 2 token 不可用 3 token 已过期
     * @throws Exception
     */
    public function validate(string $jwt): int
    {
        $time     = time();
        $parseJwt = $this->parse($jwt);

        $validateHeader  = base64_encode(json_encode($parseJwt['header'], JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        $validatePayload = base64_encode(json_encode($parseJwt['payload'], JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));

        switch ( strtoupper($parseJwt['header']['alg']) )
        {
            case 'MD5' :

                $validateSignature = md5($validateHeader . '.' . $validatePayload . $this->getSecret());

                break;

            case 'HS256' :

                $validateSignature = hash_hmac('sha256', $validateHeader . '.' . $validatePayload, $this->getSecret());

                break;

            default :

                throw new Exception('Unsupported encryption algorithm');
        }

        if ( (string) $validateSignature !== (string) $parseJwt['signature'] ) return 1;

        if ( $time < $parseJwt['payload']['nbf'] ) return 2;

        if ( $time > $parseJwt['payload']['exp'] ) return 3;


        return 0;
    }

}
