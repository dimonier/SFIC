<?php

// Simple File Integrity Checker v1.1
// Source: https://github.com/dimonier/SFIC/

/*************************************
 * Settings - Please EDIT values below
 **************************************/

$time_start = microtime(true);
echo "<html><pre>";

// Start scan from the directory when the script resides or specify address
$scandir = dirname($_SERVER['SCRIPT_FILENAME']);
// $scandir = '/home/users/d/dima/';

// Detect server name or specify manually
if(isset($_SERVER['HTTP_HOST'])) {
        $servername = $_SERVER['HTTP_HOST'];
} elseif(isset($_SERVER['SERVER_NAME'])) {
        $servername = $_SERVER['SERVER_NAME'];
} else {
$servername ="Unknown";
}

$datafilename = "data.sfic";
$logfilename = "sfic.log";

 date_default_timezone_set("UTC");
/**
 * Exclude File List - Separate each entry with a semicolon ;
 * Full filename including path and extension. [CASE INSENSITIVE]
 */
$excludeFileList = "administrator/components/com_sh404sef/security/sh404SEF_AntiFlood_Data.dat;error_log;backup.zip";

/**
 * Exclude Extension List - Separate each entry with a semicolon ;
 * Only extension type. [CASE INSENSITIVE]
 * Do not leave trailing semicolon!
 */
$excludeExtensionList = "sfic;log;bak;xls";

/**
 * Exclude directory List - Separate each entry with a semicolon ;
 * Only relative dir name including trailing dir separator. [CASE INSENSITIVE]
 * Do not leave trailing semicolon!
 */
$excludeDirList = "cache/";

/**
 * Default comparison mode:
 *   attributes - by modification timestamp and size
 *   content - by file content
 */
$defaultmode = "attributes";

/**
 * Set emailAddressToAlert variable if you want an email alert from the server.
 */
$emailAddressToAlert = "admin@example.com";
$emailSubject = "Files on the '$servername' Web server have changed";

$debug = true;
/**
 * Scan Password - This value has to be sent each time to run the code.
 * Please change from the default password to anything you like
 */
$scanPassword = "pass";

/**
 * Scan Password - This value has to be sent each time to run the code.
 * Please change from the default password to anything you like
 */

function slog($string) {
    global $logfilename;
    $loghandle=fopen($logfilename,"a");
    fwrite($loghandle,$string);
    fclose($loghandle);
}
/**********************************************************
 * Start with logic of scanning and checking the code files
 ***********************************************************/

//Key steps in scan
//STEP 1  - Check if the password is OK. Currently disabled due to a bug
	if (strcmp ( $_REQUEST["password"], $scanPassword )  != 0 )
	{
		echo "Failed to start as password is incorrect!";
		if(!$debug) exit(0);
	}

//STEP 2  - Check if user has sent the mode (otherwise use default mode)

$mode = $defaultMode;

$availableModes = ['attributes', 'content'];
if(isset($_REQUEST['mode']) && in_array($_REQUEST['mode'], $availableModes)){
$mode = $_REQUEST['mode'];
}

//STEP 2 - prepare exclusion data

if (isset($excludeDirList)) {
    $offdir=explode(';',strtolower($excludeDirList));
} else {
    $offdir=array();
}

if (isset($excludeFileList)) {
    $offfile=explode(';',strtolower($excludeFileList));
} else {
    $offfile=array();
}

if (isset($excludeExtensionList)) {
    $offext=explode(';',strtolower($excludeExtensionList));
} else {
    $offext=array();
}


//STEP 3 - Check if previously saved data exists and use it

if(substr($scandir,strlen($scandir)-1)!==DIRECTORY_SEPARATOR) $scandir.=DIRECTORY_SEPARATOR;

$olddata=array();
        if (file_exists($scandir.$datafilename)) {
    $datafile=fopen($scandir.$datafilename,"r");
    if ($datafile) {
    while (($buffer = fgets($datafile)) !== false) {
        $line=explode("\t",str_replace("\n","",$buffer));
        $entry=array(
        "namehash" => $line[0],
        "checkhash" => $line[1],
        "date" => $line[2],
        "size" => $line[3],
        "name" => $line[4],
        "ext" => $line[5],
        );
        $path_parts = pathinfo(strtolower($entry['name']));
        $processpath=true;
        foreach ($offdir as $dir)
            if($dir==substr($entry["name"],0,min(strlen($dir),strlen($entry["name"]))))
                    $processpath=false;
        $fpath=substr($entry['name'],0,strlen($entry['name'])-strlen($path_parts['basename']));
        if(!(in_array(strtolower($entry['ext']),$offext)) && $processpath && !(in_array(strtolower($entry['name']),$offfile))) {
            $olddata[$line[0]]=$entry;
        }
    }
    fclose($datafile);
}
}
if(count($olddata)>0) $oldsettings=array_shift($olddata);

if (!file_exists($scandir)) {
 slog("Directory $scandir does not exist.\n");
 exit (2);
}
$changed=array();
$deleted=array();
$added=array();
$newdata=array();
slog(date("Y-m-d H:i:s")."  Processing '$scandir'\n");
$it = new RecursiveDirectoryIterator($scandir);
$iterator = new RecursiveIteratorIterator($it);
$fff = iterator_to_array($iterator, true);

foreach($fff as $filename) {
$shortname=substr($filename, strlen($scandir));
$justname=basename($filename);
$fpath=substr($shortname,0,strlen($shortname)-strlen($justname));
$path_parts = pathinfo($filename);
$extension=strtolower($path_parts ['extension']);

        $processpath=true;
        foreach ($offdir as $dir)
            if($dir==substr($shortname,0,min(strlen($dir),strlen($shortname))))
                    $processpath=false;

        if(!in_array(strtolower($extension),$offext) && $processpath && !in_array(strtolower($shortname),$offfile)) {

    switch ($mode) {
        case 'attributes':
            $fhash=md5(filesize($filename).filemtime($filename));
            break;
        case 'content':
            $fhash=md5_file($filename);
            break;
        default:
            $fhash="Wrong mode specified";
    }

    $filedata=array(
        "namehash" => md5($shortname),
        "checkhash" => $fhash,
        "date" => date("Y-m-d H:i:s",filemtime($filename)),
        "size" => filesize($filename),
        "name" => $shortname,
        "ext" => $extension,
        );

$newdata[$filedata["namehash"]]=$filedata;

if(isset($olddata[$filedata["namehash"]])) {
    if($olddata[$filedata["namehash"]]["checkhash"]==$filedata["checkhash"]) {
    } else {
        $changed[$filedata["namehash"]]["old"]=$olddata[$filedata["namehash"]];
        $changed[$filedata["namehash"]]["new"]=$filedata;
    }
    unset($olddata[$filedata["namehash"]]);
} else {
    if(stripos($filedata["checkhash"],"excluded")===false) $added[$filedata["namehash"]]=$filedata;
}

}
}
If(count($olddata)>0) {
    foreach($olddata as $index=>$filedata) {
        if(stripos($filedata["checkhash"],"excluded")===false) $deleted[$index]=$filedata;
    }

}

//STEP 4 - Notify admin in case of changes
$changes ="";
if(count($changed)>0) {
    $changes .= "Changed:\n";
    foreach($changed as $filedata) $changes .= " ".$filedata["old"]["name"]." (".$filedata["old"]["date"]."), ".$filedata["old"]["size"]." -> ".$filedata["new"]["size"]." bytes\n";
    $changes .= "\n";
}
if(count($added)>0) {
    $changes .= "Added:\n";
    foreach($added as $filedata) $changes .= " ".$filedata["name"]." (".$filedata["date"]."), ".$filedata["size"]." bytes\n";
    $changes .= "\n";
}
if(count($deleted)>0) {
    $changes .= "Deleted:\n";
    foreach($deleted as $filedata) $changes .= " ".$filedata["name"]." (".$filedata["date"]."), ".$filedata["size"]." bytes\n";
    $changes .= "\n";
}
echo $changes;
$summary=count($newdata)." files scanned, ".count($changed)." changed, ".count($added)." added, ".count($deleted)." deleted\n";

if(count($changed)+count($added)+count($deleted)>0) {
    if($emailAddressToAlert <> ""){
   $headers = "Return-path: $emailAddressToAlert\r\n";
                $headers .= "Reply-to: $emailAddressToAlert\r\n";
                $headers .= "Content-Type: text/plain\r\n";
                $headers .= "Content-Transfer-Encoding: 7bit\r\n";
                $headers .= "From: $emailAddressToAlert\r\n";
                $headers .= "X-Priority: 3\r\n";
                $headers .= "MIME-Version: 1.0\r\n";
                $headers .= "Organization: $servername\r\n";
                $headers .= "\n\n";
			//Add the new hash value to the email
        $emailBody = "Some files in the '$scandir' folder have changed since ".$oldsettings["date"].".\n".$summary."\n".
                $changes. "\nScanned in ".(microtime(true)-$time_start)." seconds.\n";

			mail($emailAddressToAlert, $emailSubject, $emailBody, $headers); //Simple mail function for alert.

		}

}
slog($summary);

// Write new data to a file

$datafile=fopen($scandir.$datafilename,"w");
fwrite($datafile,"---\t---\t".date("Y-m-d H:i:s")."\t---\t".$scandir."\t".$mode."\n");
foreach($newdata as $filedata) fwrite($datafile,$filedata["namehash"]."\t".$filedata["checkhash"]."\t".$filedata["date"]."\t".$filedata["size"]."\t".$filedata["name"]."\t".$filedata["ext"]."\n");
fclose($datafile);
slog(date("Y-m-d H:i:s")."  Done in ".(microtime(true)-$time_start)." seconds!\n\n");
echo "\nDone in ".(microtime(true)-$time_start)." seconds!</pre></html>";

?>
