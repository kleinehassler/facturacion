<?php

class Pem{
    protected $path;

    public function __construct($path){
        $this->path = $path;
    }

    public function privateKeys(){
        $file = file_get_contents($this->path);
        $array = explode("-----BEGIN PRIVATE KEY-----", $file);
        $keys = [];
        for ($i=1; $i < count($array); $i++) { 
            $temp = explode("-----END PRIVATE KEY-----", $array[$i]);
            $key = '-----BEGIN PRIVATE KEY-----'."\n";
            $key .= trim($temp[0])."\n";
            $key .= '-----END PRIVATE KEY-----'."\n";
            $keys[] = $key;
        }
        return $keys;
    }
}