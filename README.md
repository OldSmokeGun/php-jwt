### 适用于 `PHP` 的 `JWT` 扩展包

### 使用：

- 注意：密钥必须设置

- 生成 `token`

```php
$jwt = new \oldSmokeGun\Jwt\Jwt();
              
$token = $jwt->setSecret('secret') // 设置密钥
    ->setAlg('md5') // 设置加密方式
    ->setIss('张三') // 设置签发者  
    ->setSub('测试') // 设置主题
    ->setAud('王五') // 设置接收者
    ->setExp(time() + 7200) // 设置过期时间
    ->setNbf(time()) // 设置 token 生效时间
    ->setExtraData([ // 设置额外数据
        'name' => '李四',
        'age'  => 18
    ])
    ->build();
```

- 校验

```php
$jwt = new \oldSmokeGun\Jwt\Jwt();

$result = $jwt->setSecret('secret')
              ->validate('eyJ0eXBlIjoiSldUIiwiYWxnIjoibWQ1In0=.eyJpc3MiOiLlvKDkuIkiLCJzdWIiOiLmtYvor5UiLCJhdWQiOiLnjovkupQiLCJleHAiOjE1NzU5NjY1MTksIm5iZiI6MTU3NTk1OTMxOSwiaWF0IjoxNTc1OTU5MzE5LCJqdGkiOiI1MTBmYmI0ZmIyMTNmNzA1MmFmMjk3ZDFiNjEwZDU4MiIsInB1YiI
          6W10sInByaSI6W119.73ac0c3d5f7d8a8f85c2d91418976b83');

switch ( $result )
{
    case 0 :
        echo 'token 有效';
        break;
    case 1 :
        echo '签名验证错误';
        break;
    case 2 :
        echo 'token 不可用';
        break;
    case 3 :
        echo 'token 已过期';
        break;
}
```

- `token` 解析

```php
$jwt = new \oldSmokeGun\Jwt\Jwt();

$data = $jwt->parse('eyJ0eXBlIjoiSldUIiwiYWxnIjoibWQ1In0=.eyJpc3MiOiLlvKDkuIkiLCJzdWIiOiLmtYvor5UiLCJhdWQiOiLnjovkupQiLCJleHAiOjE1NzU5NjY1MTksIm5iZiI6MTU3NTk1OTMxOSwiaWF0IjoxNTc1OTU5MzE5LCJqdGkiOiI1MTBmYmI0ZmIyMTNmNzA1MmFmMjk3ZDFiNjEwZDU4MiIsInB1YiI
        6W10sInByaSI6W119.73ac0c3d5f7d8a8f85c2d91418976b83');
```