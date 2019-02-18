<?php


$CA_KEY="ca/private/ca.key.pem";
$CA_KEY_ENC="ca/private/enc.ca.key.pem";
$CA_CERT="ca/certs/ca.cert.pem";
$CA_PASS="12345678";

$ClientCertMaxDays = 1;

function gencert($csr, $CA_CERT, $CA_KEY_ENC, $CA_PASS, $days=1)
{

	error_log(print_r(openssl_csr_get_subject($csr), true));

	putenv('PHP_PASS_SUBJECTALTNAME=' . "DNS:testqwertz.tld");

	$configArgs = array("x509_extensions" => "v3_req");
	$cert = openssl_csr_sign($csr, "file://$CA_CERT", array(file_get_contents($CA_KEY_ENC), "$CA_PASS"), $days, $configArgs);
	openssl_x509_export($cert, $certout);
	#error_log(print_r(openssl_x509_parse($certout), true));
	return $certout;
}

// arguments
$days  = $_POST['days'];
$csr = $_POST['csr'];

// server side maximum values: maxmimum client certificate lifetime
if($days > $ClientCertMaxDays){
    $days = $ClientCertMaxDays;
}


Header("Content-Type: application/x-x509-user-cert");
echo gencert($csr, $CA_CERT, $CA_KEY_ENC, $CA_PASS, $days);
end:

?>

