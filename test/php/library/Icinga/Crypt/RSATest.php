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
    function testLoadKeyThrowsExceptionIfMoreThanTwoKeysGiven()
    {
        (new RSA())->loadKey('one','two','three');
    }

    /**
     * @expectedException UnexpectedValueException
     */
    function testGetPublicKeyThrowsExceptionIfNoPublicKeySet()
    {
        (new RSA())->getPublicKey();
    }

    /**
     * @expectedException UnexpectedValueException
     */
    function testGetPrivateKeyThrowsExceptionIfNoPrivateKeySet()
    {
        (new RSA())->getPrivateKey();
    }

    function testLoadKeyAutomaticallyDetectsThePublicAndPrivateKey()
    {
        list($privateKey, $publicKey) = RSA::keygen();

        $rsa = (new RSA())->loadKey($publicKey, $privateKey);
        $this->assertSame($privateKey, $rsa->getPrivateKey());
        $this->assertSame($publicKey, $rsa->getPublicKey());

        $rsa = (new RSA())->loadKey($privateKey, $publicKey);
        $this->assertSame($privateKey, $rsa->getPrivateKey());
        $this->assertSame($publicKey, $rsa->getPublicKey());
    }

    function testEncryptReturnEmptyArrayIfNoParameterGivenAndReturnEncryptedValueIfParameterIsGiven()
    {
        $rsa = (new RSA())->loadKey(...RSA::keygen());
        $this->assertSame(empty($rsa->encrypt()), true);
        $this->assertSame(empty($rsa->encrypt('one')), false);
        $this->assertSame(empty($rsa->encrypt(false)), false);
        $this->assertSame(empty(array_filter($rsa->encrypt())), true);
        $this->assertSame(empty(array_filter($rsa->encrypt('one'))), false);
    }

    function testEncryptToBase64ReturnEmptyArrayIfNoParameterGivenAndReturnEncryptedValueIfParameterIsGiven()
    {
        $rsa = (new RSA())->loadKey(...RSA::keygen());
        $this->assertSame(empty($rsa->encryptToBase64()), true);
        $this->assertSame(empty($rsa->encryptToBase64('one')), false);
        $this->assertSame(empty($rsa->encryptToBase64(false)), false);
        $this->assertSame(empty(array_filter($rsa->encryptToBase64())), true);
        $this->assertSame(empty(array_filter($rsa->encryptToBase64('one'))), false);
    }

    function testDecryptReturnEmptyArrayIfNoParameterGivenAndReturnEncryptedValueIfParameterIsGiven()
    {
        $rsa = (new RSA())->loadKey(...RSA::keygen());
        $encrypted = $rsa->encrypt('one');
        $this->assertSame($rsa->decrypt(...$encrypted), ['one']);
        $this->assertSame(empty($rsa->decrypt()), true);
        $this->assertSame(empty($rsa->decrypt(...$encrypted)), false);
        $this->assertSame(empty(array_filter($rsa->decrypt())), true);
        $this->assertSame(empty(array_filter($rsa->decrypt(...$encrypted))), false);
    }

    function testDecryptFromBase64ReturnEmptyArrayIfNoParameterGivenAndReturnEncryptedValueIfParameterIsGiven()
    {
        $rsa = (new RSA())->loadKey(...RSA::keygen());
        $encrypted = $rsa->encryptToBase64('one');
        $this->assertSame($rsa->decryptFromBase64(...$encrypted), ['one']);
        $this->assertSame(empty($rsa->decryptFromBase64()), true);
        $this->assertSame(empty($rsa->decryptFromBase64(...$encrypted)), false);
        $this->assertSame(empty(array_filter($rsa->decryptFromBase64())), true);
        $this->assertSame(empty(array_filter($rsa->decryptFromBase64(...$encrypted))), false);
    }
}
