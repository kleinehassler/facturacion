<?php

class Firma{

    protected $path;

    protected $xml;
    
    protected $xml_file;

    protected $xml_firmado;

    protected $xml_name;

    protected $cert;
    
    protected $cert_data;

    protected $pkey;

    public function __construct($path, $cert, $pkey){
        $this->path = $path;
        $this->pkey = $pkey;
        $this->xml_file = file_get_contents($path);
        $this->xml_name = trim(basename($path));
        $this->xml = simplexml_load_string($this->xml_file);
        $this->cert = $this->get_cert($cert);
        $this->cert_data = $this->get_cert_data($this->cert['extracerts'][0]);
    }

    protected function get_cert($cert){
        if (openssl_pkcs12_read(file_get_contents($cert), $info_cert, "cc19540AB")) {
            return $info_cert;
        } else {
            die("Error al leer el certificado!.");
        }
    }

    protected function get_cert_data($cert){
        return openssl_x509_parse($cert);
    }

    public function getID() {          
        $certificado = $this->cert['extracerts'][0];
        $certificado = str_replace('-----BEGIN CERTIFICATE-----', "", $certificado);
        $certificado = str_replace('-----END CERTIFICATE-----', "", $certificado);
        $certificado = str_replace("\n", "", $certificado);
        $certificado = str_split($certificado, 76);
        $certificado = implode("\n", $certificado);
        $certificado_b64 = str_replace("\n", "", $certificado);
        $cert = base64_encode(hash("sha1", base64_decode($certificado_b64), true));
        return $cert;
    }

    public function firma(){
        $clave_acceso = $this->xml->infoTributaria->claveAcceso;
        $doc = new DOMDocument();
        $doc->load($this->path);
        $sha1_factura = $this->sha1_base64($doc->C14N());
        $xmlns = 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:etsi="http://uri.etsi.org/01903/v1.3.2#"';
        
        //numeros involucrados en los hash:
        $Certificate_number = $this->p_obtener_aleatorio(); //1562780 en el ejemplo del SRI
        $Signature_number = $this->p_obtener_aleatorio(); //620397 en el ejemplo del SRI
        $SignedProperties_number = $this->p_obtener_aleatorio(); //24123 en el ejemplo del SRI
        
        //numeros fuera de los hash:
        $SignedInfo_number = $this->p_obtener_aleatorio(); //814463 en el ejemplo del SRI
        $SignedPropertiesID_number = $this->p_obtener_aleatorio(); //157683 en el ejemplo del SRI
        $Reference_ID_number = $this->p_obtener_aleatorio(); //363558 en el ejemplo del SRI
        $SignatureValue_number = $this->p_obtener_aleatorio(); //398963 en el ejemplo del SRI
        $Object_number = $this->p_obtener_aleatorio(); //231987 en el ejemplo del SRI

        $certificateX509_der_hash = $this->getID();
        
        $X509SerialNumber = $this->cert_data["serialNumber"];
        $SignedProperties = '';

        $SignedProperties .='<etsi:SignedProperties Id="Signature'.$Signature_number.'-SignedProperties'.$SignedProperties_number.'">';  //SignedProperties
            $SignedProperties .='<etsi:SignedSignatureProperties>';
                $SignedProperties .='<etsi:SigningTime>';
                $SignedProperties .= date('Y-m-d\TH:i:s-05:00');
                    
                $SignedProperties .= '</etsi:SigningTime>';
                $SignedProperties .= '<etsi:SigningCertificate>';
                    $SignedProperties .= '<etsi:Cert>';
                        $SignedProperties .= '<etsi:CertDigest>';
                            $SignedProperties .= '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>';
                            //$SignedProperties .= '</ds:DigestMethod>';
                            $SignedProperties .= '<ds:DigestValue>';

                                $SignedProperties .= $certificateX509_der_hash;

                            $SignedProperties .= '</ds:DigestValue>';
                        $SignedProperties .= '</etsi:CertDigest>';
                        $SignedProperties .= '<etsi:IssuerSerial>';
                            $SignedProperties .= '<ds:X509IssuerName>';
                                $SignedProperties .= 'CN=AC BANCO CENTRAL DEL ECUADOR,L=QUITO,OU=ENTIDAD DE CERTIFICACION DE INFORMACION-ECIBCE,O=BANCO CENTRAL DEL ECUADOR,C=EC';
                            $SignedProperties .= '</ds:X509IssuerName>';
                        $SignedProperties .= '<ds:X509SerialNumber>';
        
                            $SignedProperties .= $X509SerialNumber;
                            
                        $SignedProperties .= '</ds:X509SerialNumber>';
                        $SignedProperties .= '</etsi:IssuerSerial>';
                    $SignedProperties .= '</etsi:Cert>';
                $SignedProperties .= '</etsi:SigningCertificate>';
            $SignedProperties .= '</etsi:SignedSignatureProperties>';
            $SignedProperties .= '<etsi:SignedDataObjectProperties>';
                $SignedProperties .= '<etsi:DataObjectFormat ObjectReference="#Reference-ID-'. $Reference_ID_number.'">';
                    $SignedProperties .= '<etsi:Description>';
                        
                        $SignedProperties .= 'contenido comprobante';                        

                    $SignedProperties .= '</etsi:Description>';
                    $SignedProperties .= '<etsi:MimeType>';
                        $SignedProperties .= 'text/xml';
                    $SignedProperties .= '</etsi:MimeType>';
                $SignedProperties .= '</etsi:DataObjectFormat>';
            $SignedProperties .= '</etsi:SignedDataObjectProperties>';
        $SignedProperties .= '</etsi:SignedProperties>'; //fin SignedProperties

        $SignedProperties_para_hash = str_replace('<etsi:SignedProperties', '<etsi:SignedProperties '.$xmlns, $SignedProperties);
        $sha1_SignedProperties = $this->sha1_base64(trim($SignedProperties_para_hash));        
        
        $KeyInfo = '';
        $KeyInfo .= '<ds:KeyInfo Id="Certificate'.$Certificate_number.'">'."\n";
            $KeyInfo .= '<ds:X509Data>'."\n";
                $KeyInfo .= '<ds:X509Certificate>'."\n";

                    //CERTIFICADO X509 CODIFICADO EN Base64 
                    $KeyInfo .= $this->getCertificate(true)."\n";

                $KeyInfo .= '</ds:X509Certificate>'."\n";
            $KeyInfo .= '</ds:X509Data>'."\n";
            $KeyInfo .= '<ds:KeyValue>'."\n";
                $KeyInfo .= '<ds:RSAKeyValue>'."\n";
                    $KeyInfo .= '<ds:Modulus>'."\n";

                        //MODULO DEL CERTIFICADO X509
                        $KeyInfo .= $this->getModulus()."\n";

                    $KeyInfo .= '</ds:Modulus>'."\n";
                    $KeyInfo .= '<ds:Exponent>';
                    
                        //$KeyInfo .= 'AQAB';
                        $KeyInfo .= $this->getExponent();
                        
                    $KeyInfo .= '</ds:Exponent>'."\n";
                $KeyInfo .= '</ds:RSAKeyValue>'."\n";
            $KeyInfo .= '</ds:KeyValue>'."\n";
        $KeyInfo .= '</ds:KeyInfo>'."\n";

        $KeyInfo_para_hash = str_replace('<ds:KeyInfo', '<ds:KeyInfo '.$xmlns, $KeyInfo);
        $sha1_certificado = $this->sha1_base64(trim($KeyInfo_para_hash));
        
        $SignedInfo = "";

        $SignedInfo .= '<ds:SignedInfo Id="Signature-SignedInfo'.$SignedInfo_number.'">'."\n";
            $SignedInfo .= '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'."\n";
            //$SignedInfo .= '</ds:CanonicalizationMethod>'."\n";
            $SignedInfo .= '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'."\n";
            //$SignedInfo .= '</ds:SignatureMethod>';
            $SignedInfo .= '<ds:Reference Id="SignedPropertiesID'.$SignedPropertiesID_number.'" Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature'.$Signature_number.'-SignedProperties'.$SignedProperties_number.'">'."\n";
                $SignedInfo .= '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'."\n";
                //$SignedInfo .= '</ds:DigestMethod>'."\n";
                $SignedInfo .= '<ds:DigestValue>';

                    //HASH O DIGEST DEL ELEMENTO <etsi:SignedProperties>';
                    $SignedInfo .= $sha1_SignedProperties;

                $SignedInfo .= '</ds:DigestValue>'."\n";
            $SignedInfo .= '</ds:Reference>'."\n";
            $SignedInfo .= '<ds:Reference URI="#Certificate'.$Certificate_number.'">'."\n";
                $SignedInfo .= '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'."\n";
                //$SignedInfo .= '</ds:DigestMethod>';
                $SignedInfo .= '<ds:DigestValue>';

                    //HASH O DIGEST DEL CERTIFICADO X509
                    $SignedInfo .= $sha1_certificado;

                $SignedInfo .= '</ds:DigestValue>'."\n";
            $SignedInfo .= '</ds:Reference>'."\n";
            $SignedInfo .= '<ds:Reference Id="Reference-ID-'.$Reference_ID_number.'" URI="#comprobante">';
                $SignedInfo .= '<ds:Transforms>'."\n";
                    $SignedInfo .= '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'."\n";
                    //$SignedInfo .= '</ds:Transform>';
                $SignedInfo .= '</ds:Transforms>'."\n";
                $SignedInfo .= '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'."\n";
                //$SignedInfo .= '</ds:DigestMethod>';
                $SignedInfo .= '<ds:DigestValue>';

                    //HASH O DIGEST DE TODO EL ARCHIVO XML IDENTIFICADO POR EL id="comprobante" 
                    $SignedInfo .= $sha1_factura;

                $SignedInfo .= '</ds:DigestValue>'."\n";
            $SignedInfo .= '</ds:Reference>'."\n";
        $SignedInfo .= '</ds:SignedInfo>'."\n";
        
        $SignedInfo_para_firma = str_replace('<ds:SignedInfo', '<ds:SignedInfo '.$xmlns, $SignedInfo);
        $firma = $this->sign(trim($SignedInfo_para_firma));
        $signature = wordwrap($this->removeSpaces($firma), 76, "\n", true);
         $xades_bes = '';
        //INICIO DE LA FIRMA DIGITAL 
            $xades_bes .= '<ds:Signature '.$xmlns.' Id="Signature'.$Signature_number.'">'."\n";
                $xades_bes .= $SignedInfo;

                $xades_bes .= '<ds:SignatureValue Id="SignatureValue'.$SignatureValue_number.'">'."\n";

                    //VALOR DE LA FIRMA (ENCRIPTADO CON LA LLAVE PRIVADA DEL CERTIFICADO DIGITAL) 
                    $xades_bes .= $signature."\n";

                $xades_bes .= '</ds:SignatureValue>'."\n";

                $xades_bes .= $KeyInfo;

                $xades_bes .= '<ds:Object Id="Signature'.$Signature_number.'-Object'.$Object_number.'">';
                    $xades_bes .= '<etsi:QualifyingProperties Target="#Signature'.$Signature_number.'">';

                        //ELEMENTO <etsi:SignedProperties>';
                        $xades_bes .= $SignedProperties;

                    $xades_bes .= '</etsi:QualifyingProperties>';
                $xades_bes .= '</ds:Object>';
            $xades_bes .= '</ds:Signature>';
            //FIN DE LA FIRMA DIGITAL 
        return $xades_bes;
    }

    public function firmar_documento(){
        $firma = $this->firma();
        $xml = $this->xml_file;
        $documento = str_replace("</comprobanteRetencion>", $firma."</comprobanteRetencion>", $xml);
        $documento = str_replace("</factura>", $firma."</factura>", $documento);
        $documento = str_replace("</notaCredito>", $firma."</notaCredito>", $documento);
        $documento = str_replace("</guiaRemision>", $firma."</guiaRemision>", $documento);
        $documento = str_replace("</notaDebito>", $firma."</notaDebito>", $documento);
        return $documento;
    }

    public function getFileName(){
        return trim($this->xml_name);
    }

    protected function p_obtener_aleatorio() {
        return round((rand(1, 1000) * 999000) + 990, 0, PHP_ROUND_HALF_UP);    
    }

    protected function sha1_base64($value) {
        //return base64_encode(sha1($value, true));
        return base64_encode(pack("H*", sha1($value)));
    }

    private function getCertificate($clean = false)
    {
        $cert = trim(preg_replace('/\s\s+/', ' ', $this->cert['extracerts'][0]));
        if ($clean) {
            $cert = trim(str_replace(
                ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'],
                '',
                $cert
            ));
        }
        return wordwrap($this->removeSpaces($cert), 76, "\n", true);
    }

    private function removeSpaces($value){
        return preg_replace( "/\r|\n/", "", $value);
    }

    private function getPrivateKey($clean = false)
    {
        $pkey = trim(preg_replace('/\s\s+/', ' ', $this->cert['pkey']));
        if ($clean) {
            return trim(str_replace(
                ['-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----'],
                '',
                $pkey
            ));
        } else {
            return $pkey;
        }
    }

    private function getModulus()
    {
        if($this->pkey){
            $details = openssl_pkey_get_details(openssl_pkey_get_private($this->pkey[1]));
        }else{
            $details = openssl_pkey_get_details(openssl_pkey_get_private($this->certs['pkey']));
        }
        $details = base64_encode(@$details["rsa"]["n"]);
        return wordwrap($this->removeSpaces($details), 76, "\n", true);
    }

    private function getExponent()
    {
        if($this->pkey){
            $details = openssl_pkey_get_details(openssl_pkey_get_private($this->pkey[1]));
        }else{
            $details = openssl_pkey_get_details(openssl_pkey_get_private($this->certs['pkey']));
        }
        $details = base64_encode(@$details["rsa"]["e"]);
        return wordwrap($this->removeSpaces($details), 76, "\n", true);
    }

    /**
     * Método para realizar la firma de datos
     * @param data Datos que se desean firmar
     * @param signature_alg Algoritmo que se utilizará para firmar (por defect SHA1)
     * @return Firma digital de los datos en base64 o =false si no se pudo firmar
     */

    private function sign($data, $signature_alg = OPENSSL_ALGO_SHA1)
    {
        $signature = null;
        if (openssl_sign($data, $signature, $this->pkey[1], $signature_alg)==false) {
            return die('No fue posible firmar los datos');
        }
        return base64_encode($signature);
    }
}