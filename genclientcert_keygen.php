<?php
include 'phpseclib/autoload.php';


$CA_KEY="ca/private/ca.key.pem";
$CA_CERT="ca/certs/ca.cert.pem";

$dn = [];
$dn['commonName'] = "";
$dn['countryName'] = "";
$dn['stateOrProvinceName'] = "";
$dn['organizationName'] = "";
$dn['organizationalUnitName'] = "";
$ClientCertMaxDays = 1;

function gencert($publickey, $cacert, $cakey, $dn, $e, $serial, $days = 365)
{
        #$caPrivateKey = new Crypt_RSA();
        $caPrivateKey = new phpseclib\Crypt\RSA();
        $caPrivateKey->loadKey($cakey);

        $issuer = new phpseclib\File\X509();
        $issuer->loadX509($cacert);
        $issuer->setPrivateKey($caPrivateKey);

	$pubKey = new phpseclib\Crypt\RSA(); 
	$pubKey->loadKey($publickey); 

    	$subject = new phpseclib\File\X509();
        $subject->loadCA($cacert);
        #$subject->loadSPKAC($spkac);
	$subject->setPublicKey($pubKey);
        $subject->setDNProp('CN', $dn['commonName']);
        $subject->setDNProp('C' , $dn['countryName']);
        $subject->setDNProp('ST', $dn['stateOrProvinceName']);
        $subject->setDNProp('O' , $dn['organizationName']);
        $subject->setDNProp('OU', $dn['organizationalUnitName']);
        $subject->setDNProp('emailAddress' , $e);

        $x509 = new phpseclib\File\X509();
        $x509->setSerialNumber($serialNumber = $serial, 10);
        $x509->setEndDate('+'.$days.' days');
        $result = $x509->sign($issuer, $subject);
        $format = (false !== strpos($_SERVER['HTTP_USER_AGENT'], 'Chrome')) ? 1 : 0;
        return $x509->saveX509($result, $format);
}

$caKey = file_get_contents($CA_KEY);
$caCert = file_get_contents($CA_CERT);

error_log("caKey = ". $caKey);

// arguments
$cn    = $_POST['cn'];
$days  = $_POST['days'];
$pubkey = $_POST['pubkey'];


error_log("cn = ". $cn);
error_log("days = ". $days);
#error_log("spkac = ". $spkac);
error_log("pubkey = ". $pubkey);

// server side maximum values: maxmimum client certificate lifetime
if($days > $ClientCertMaxDays){
        $days = $ClientCertMaxDays;
}

if (255 < strlen($cn)){
        echo "cannot create certificate, email address (here smartrns address) too long: " . strlen($cn) . " > 255 characters";
        error_log("cannot create certificate, email address (here smartrns address) too long: " . strlen($cn) . " > 255 characters");
        goto end;
}

// time
date_default_timezone_set('UTC');
$date = new DateTime();
$now = $date->getTimestamp();

$serial = hexdec('133700000000');

Header("Content-Type: application/x-x509-user-cert");

echo gencert($pubkey, $caCert, $caKey, $dn, $cn, $serial, $days);


end:

?>

