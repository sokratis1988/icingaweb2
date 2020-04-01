<?php
// Icinga Web 2 | (c) 2020 Icinga Development Team | GPLv2+

namespace Tests\Icinga\Crypt;

use Icinga\Crypt\RSA;
use Icinga\Test\BaseTestCase;
use InvalidArgumentException;
use UnexpectedValueException;

class RSATest extends BaseTestCase
{
    /**
     * @expectedException InvalidArgumentException
     */
    public function testLoadKeyThrowsExceptionIfMoreThanTwoKeysGiven()
    {
        (new RSA())->loadKey('one','two','three');
    }

    /**
     * @expectedException UnexpectedValueException
     */
    public function testGetPublicKeyThrowsExceptionIfNoPublicKeySet()
    {
        (new RSA())->getPublicKey();
    }

    /**
     * @expectedException UnexpectedValueException
     */
    public function testGetPrivateKeyThrowsExceptionIfNoPrivateKeySet()
    {
        (new RSA())->getPrivateKey();
    }
    public function testLoadKeyAutomaticallyDetectsThePublicAndPrivateKey()
    {
        list($privateKey, $publicKey) = RSA::keygen();

        $rsa = (new RSA())->loadKey($publicKey, $privateKey);
        $this->assertSame($privateKey, $rsa->getPrivateKey());
        $this->assertSame($publicKey, $rsa->getPublicKey());

        $rsa = (new RSA())->loadKey($privateKey, $publicKey);
        $this->assertSame($privateKey, $rsa->getPrivateKey());
        $this->assertSame($publicKey, $rsa->getPublicKey());
    }

    public function testEncryptReturnsEmptyArrayIfNoArgumentsGiven()
    {
        $rsa = (new RSA())->loadKey(...RSA::keygen());
        $this->assertSame([], $rsa->encrypt());
    }

    public function testEncryptionAndDecryption()
    {
        $rsa = (new RSA())->loadKey(...RSA::keygen());

        $data = ['foo', 'bar'];

        $this->assertSame($data, $rsa->decrypt(...$rsa->encrypt(...$data)));
    }

    public function testEncryptionToBase64AndDecryptionFromBase64()
    {
        $rsa = (new RSA())->loadKey(...RSA::keygen());

        $data = ['foo', 'bar'];

        $this->assertSame($data, $rsa->decryptFromBase64(...$rsa->encryptToBase64(...$data)));
    }
    
    public function testDecryptReturnsExactSameValuesAsEncrypted()
    {
        $rsa = (new RSA())->loadKey(...RSA::keygen());
        $data = ['int' => 1, 'float' => 1.1, 'yes' => true, 'no' => false, 'null' => null, 'empty-string' => ''];
        $encodedData = json_encode($data);
        $encrypted = $rsa->encrypt($encodedData);
        $decrypted = $rsa->decrypt(...$encrypted);
        $decodedData = json_decode($decrypted[0],true);
        $this->assertSame($decodedData, $data);

    }
}