<?php
  require_once("Free20requests.php");

  $phone    = "0630786817"; //เบอร์วอลเลต
  $password = "savat2211"; //รหัสผ่านวอลเลต
  $access_token = "@TOKEN" //ได้รับหลังจากยืนยัน OTP

  $tw = new TrueWallet($phone, $password);
  
  /*
  
  #STEP1
  print_r($tw->RequestLoginOTP());
  
  #STEP2
  print_r($tw->SubmitLoginOTP('986378', $phone, 'WXXJ'));  
  
  */
  
  $tw->setAccessToken($access_token);
  $data = $tw->GetTransaction();
  print_r($data);
  
?>
