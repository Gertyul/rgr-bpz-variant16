<?php

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	// РГР-ВИПРАВЛЕННЯ V3: ідентифікатор сесії формується криптографічно стійким
	// генератором випадкових байтів замість послідовного лічильника, тому його
	// не можна передбачити. Прапорці HttpOnly/SameSite унеможливлюють крадіжку.
	$cookie_value = bin2hex( random_bytes( 16 ) );
	setcookie( "dvwaSession", $cookie_value, 0, "/", "", false, true );
}
?>
