<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	// РГР-ВИПРАВЛЕННЯ V3: випадкове значення замість time() + прапорці безпеки.
	$cookie_value = bin2hex( random_bytes( 16 ) );
	setcookie( "dvwaSession", $cookie_value, 0, "/", "", false, true );
}
?>
