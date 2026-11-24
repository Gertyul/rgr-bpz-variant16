<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	// РГР-ВИПРАВЛЕННЯ V3: md5(лічильник) передбачуване — замінено на випадкове
	// значення; додано прапорці HttpOnly (останній аргумент) та SameSite через options.
	$cookie_value = bin2hex( random_bytes( 16 ) );
	setcookie( "dvwaSession", $cookie_value, [
		'expires'  => time() + 3600,
		'path'     => "/vulnerabilities/weak_id/",
		'httponly' => true,
		'samesite' => 'Lax',
	] );
}

?>
