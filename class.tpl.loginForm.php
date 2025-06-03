<?php
/**
 * @filename class.tpl.loginFormBCYPT.php
 * all login related functions contained within
 * 
 * @author Gopinath v <gopinath@infinitisoftware.net>
 */

/* file includes */
fileRequire("dataModels/class.corporateHomePageDetails.php");
fileRequire("dataModels/class.userDetails.php");
fileRequire("dataModels/class.corporateDetails.php");
fileRequire("dataModels/class.userPasswordMapping.php");
fileRequire("dataModels/class.loginVerification.php");
fileRequire("classes/class.common.php");
fileRequire("classes/class.encrypt.php");

/**
 * interface login
 * 
 * @author Gopinath v <gopinath@infinitisoftware.net>
 */
interface login{

    const TARESTRICTION = 'TARESTRICTION';

    const LOGINOK = 'OK';

    const LOGINCODE = 'CODELOGIN';

    const CODENOTACCEPTED = 'VERIFICATIONERROR';

    const CORPORATE = 'CORPORATE';

    const EMAILVERIFY = 'EMAILVERIFY';

    const ACCOUNTBLOCK = 'ACCOUNTBLOCK';

    const APPROVAL = 'APPROVAL';

    const PASSWORD = 'PASSWORD';

    const EMAIL = 'EMAIL';
    
    const SSOLOGIN="SSOLOGIN";

    const ACCOUNT_ALREADY_ACTIVE = "ACCOUNT_ALREADY_ACTIVE";

    const APILOGIN="APILOGIN";

    const REGISTRATIONPAYMENT = 'REGISTRATIONPAYMENT';

    const CAPTCHAREQUIRED = 'CAPTCHAREQUIRED';

    const DIRECT_LOGIN_RESTRICTION = 'DIRECT_LOGIN_RESTRICTION';
    
    /* authenticate user */
    public function _login();
}


/**
 * interface pwdExpiry
 * 
 * @author Gopinath v <gopinath@infinitisoftware.net>
 */
interface pwdExpiry{

    const PASSWORDCHANGE = 'PASSWORDCHANGE';

    const PASSWORDEXPIRYVALIDATION = 'PASSWORDEXPIRYVALIDATION';

    const PWDEXPIRYOK = 'OK';

    /* pwd expiry config */
    public function _checkPasswordExpiry();
}



/**
 * interface pwdUpgrade
 * 
 * @author Gopinath v <gopinath@infinitisoftware.net>
 */
interface pwdUpgrade{

    /* pwd upgrade config */
    public function _isUpgrade();

    /* automatically upgrade pwd on successfull login */
    public function _isSlilentUpgrade();

    /* check db column property is capable for upgrade */
    public function _isDBValueSuitable();

    /* get user's pwd type in database */
    public function _getUserPwdType($_Susername);
}

/**
 * interface captchaVerify
 */
interface captchaVerify{

    const WRONGCAPTCHA = 'WrongCaptcha';
    const NOTAVALIDUSER = 'Not a valid user';

    /* captcha vaidation */
    public function _checkCaptcha();
    
}

/**
 * class passwordBCrypt
 * handles pwd upgrade from md5 bcrypt
 * 
 * @author Gopinath v <gopinath@infinitisoftware.net>
 */
class passwordBCrypt implements pwdUpgrade{

    const PWD_MD5 = 'PWD_MD5';
    const PWD_BCRYPT = 'PWD_BCRYPT';

    public function __construct($connection){
        $this->_Oconnection = $connection;
        $this->_Ocommon = new Common();
        $this->_Ocommon->_Oconnection = $connection;
    }

    public function setInputData($_AInputData){
        $this->_IinputData = $_AInputData;
    }

    public function _isUpgrade(){
        return ($this->_Ocommon->_getGlobalConfig("password,passwordUpgrade") == 'Y');
    }

    public function _isSlilentUpgrade(){
        return ($this->_Ocommon->_getGlobalConfig("password,silentPwdUpgrade")=='Y');
    }

    public function _isDBValueSuitable(){
        return $this->_Ocommon->_checkPWDField();
    }

    /**
     * _isPassRequirements
     * 
     * @author Gopinath v <gopinath@infinitisoftware.net>
     * @return boolean true if pwd is md5, false for not md5
     */
    public function _isPassRequirements(){
        $userDetailsModel = new userDetails();
        $userDetailsModel->_Oconnection =$this->_Oconnection;
        $userDetailsModel->_SemailId = $this->_IinputData['loginUserName'];
        $user = $userDetailsModel->_selectUserDetails()[0];
        return (isset($user['user_password'])) ? 
            $this->_Ocommon->_checkHashIsMD5($user['user_password']) : false;
    }

    public function _isPassUpgradeRequirements(){
        return $this->_isUpgrade() && $this->_isSlilentUpgrade()
            && $this->_isDBValueSuitable();
    }

    public function _getUserPwdType($_Susername){
        $userDetailsModel =  new userDetails();
        $userDetailsModel->_Oconnection=$this->_Oconnection;

        if($this->_IinputData['usernameLogin'] == 'Y'){
            $userDetailsModel->_SuserName = $_Susername;
        } else {
            $userDetailsModel->_SemailId = $_Susername;
        }

        /*For multiple email id allowed in API login so set the password as another condition*/
        if($this->_SapiLogin == 'Y')
        {
           $userDetailsModel->_SuserPassword = $this->_IinputData['loginUserPassword']; 
        }
        $result = $userDetailsModel->_selectUserDetails()[0];
        return ($this->_Ocommon->_checkHashIsMD5($result['user_password']))?
            passwordBCrypt::PWD_MD5 : passwordBCrypt::PWD_BCRYPT;
    }
}


/**
 * abstract class authHelper
 * helers for authentication
 * 
 * @author Gopinath v <gopinath@infinitisoftware.net>
 */
abstract class authHelper implements login, pwdExpiry, captchaVerify {

    protected $_Ocommon;
    protected $passwordBCrypt;
    protected $_Osmarty;
    protected $_OobjResponse;
    protected $_IinputData;
    protected static $userDetails = null;
    private $_IcheckPasswordExpiryUserId = "";
    protected $_ObjSecurity;

    public function __construct(){
        $this->_Ocommon = new Common();
        $this->_OcorporateDetails = new corporateDetails();
        $this->_OcorporateHomePageDetails = new corporateHomePageDetails();
        
    }

    /* getters & setters */

    public function setConnection($_Oconnection){
        $this->_Oconnection = $_Oconnection;
        $this->_Ocommon->_Oconnection=$_Oconnection;
        $this->_OcorporateDetails->_Oconnection = $_Oconnection;
        $this->_OcorporateHomePageDetails->_Oconnection = $_Oconnection;
        $this->passwordBCrypt = new passwordBCrypt($_Oconnection);
        // initialise wiht connection, 
        //  since SessionDetails object will not be available in systemsetup without login
        $this->_ObjSecurity = new systemSetup($_Oconnection);
        return $this;
    }

    public function setObjResponse($_OobjResponse){
        $this->_OobjResponse = $_OobjResponse;
        return $this;
    }

    public function setInputData($_AInputData){
        $this->_IinputData = $_AInputData;
        $this->passwordBCrypt->setInputData($_AInputData);
        return $this;
    }

    public function setSmarty($_Osmarty){
        $this->_Osmarty = $_Osmarty;
        return $this;
    }

    public function setPasswordExpiryUID($_IuserId){
        $this->_IcheckPasswordExpiryUserId = $_IuserId;
        return $this;
    }

    public function getUserPasswordExpiryUID(){
        if(!is_int($this->_IcheckPasswordExpiryUserId) && $this->_IcheckPasswordExpiryUserId <= 0 )
            throw new Exception("Trying to access invalid user id");
        return $this->_IcheckPasswordExpiryUserId;
    }

    public function setAgencyTopupOption($value){
        $this->_OagencyTopupLoginCheck = $value;
        return $this;
    }
    
     public function setSSoLoginOption($value){
        $this->_SssoLoginCheck = $value;
        return $this;
    }
    public function setAPILoginOption($value){
        $this->_SapiLogin = $value;
        return $this;
    }


    /**
     * singleton userDetails since many instance of
     * userdetails are needed
     */
    
    protected static function getUserDetails(){
        if(!is_null(authHelper::$userDetails))
            return authHelper::$userDetails;
        authHelper::$userDetails = new userDetails();
    }

    public static function resetUserDetails(){
        authHelper::getUserDetails();
        authHelper::$userDetails->__construct();
        return authHelper::$userDetails;
    }




    /**
     * function _setSessionValues
     * session values set during login
     * @param array $corporateDetailsArray
     * @return void
     */
    public function _setSessionValues($corporateDetailsArray){
        global $CFG;
        $_SESSION['groupRM']['userTimeZoneInterval'] = $CFG['user'][0]['time_zone_interval'];
        $_SESSION['groupRM']['userTimeZoneKey'] = $CFG['user'][0]['time_zone_key'];
        $_SESSION['groupRM']['countryCode'] = $CFG['user'][0]['country_code'];
        $_SESSION['groupRM']['corporateTimeZoneInterval'] = $corporateDetailsArray[0]['time_zone_interval'];
        $_SESSION['groupRM']['groupUserId'] = $CFG['user'][0]['user_id'];
        $_SESSION['groupRM']['groupLoginId'] = $CFG['user'][0]['email_id'];
        $_SESSION['groupRM']['groupUserName'] = $CFG['user'][0]['first_name'];
        $_SESSION['groupRM']['groupLastName'] = $CFG['user'][0]['last_name'];
        $_SESSION['groupRM']['groupId'] = $CFG['user'][0]['group_id'];
        $_SESSION['groupRM']['groupName'] = $CFG['groupAlais'][$_SESSION['groupRM']['groupId']]['name'];
        $_SESSION['groupRM']['groupCorporateId'] = $CFG['user'][0]['corporate_id'];
        $_SESSION['groupRM']['groupCorporateTypeId'] = $corporateDetailsArray[0]['corporate_type_id'];

        // Added IATA code in the session so that it can be used to make country field as editable or non-editable 
        $_SESSION['groupRM']['groupIataCode'] = $corporateDetailsArray[0]['iata_code'];

        /*  * Inserting old password updated date to session, 
            * For the purpose of,incase password change happened user 
            * we need to logout the user from multiple browser sessions*/    
        $this->_Ocommon->_checkOldPassword($_SESSION['groupRM']['groupUserId']);
        if(!empty($this->_Ocommon->_DlastUpdatedDate))
            $_SESSION['groupRM']['passwordLastUpdatedDate']=$this->_Ocommon->_DlastUpdatedDate;              
        
        $this->_getCorporateGroupId();
        $this->_getSiteCurrencyType();

        $_SESSION['groupRM']['userTimeZoneDisplay'] = 
            $CFG["default"]["showTimezoneInGMT"] == "N" ?
            $this->_Ocommon->_showTimeZoneDifferenceInCST() :
            $this->_Ocommon->_getUserTimeZoneVal() 
        ;
        #commended this line to fetch user level settings for Al groups
        //if($_SESSION['groupRM']['groupUserTypeId']==2 && in_array($_SESSION['groupRM']['groupId'],$CFG['default']['airlinesGroupId']))
        $this->_getUserLevelSettings();
        if(in_array($_SESSION['groupRM']['groupId'],$CFG['site']['sectorMappingGroupId'])){
            $_SESSION['groupRM']['sectorMapping'] = array();
            $_AsectorManagement = $this->_Ocommon->_getSectorManagement($_SESSION['groupRM']['groupUserId'],'Y',1);
            $_SESSION['groupRM']['sectorMapping']['includeSector'] = 'N';
            if(!empty($_AsectorManagement))
                $_SESSION['groupRM']['sectorMapping']['includeSector'] = 'Y';

            $_AsectorManagement = $this->_Ocommon->_getSectorManagement($_SESSION['groupRM']['groupUserId'],'',1);
            $_SESSION['groupRM']['sectorMapping']['matchedSector'] = 'N';
            if(!empty($_AsectorManagement))
                $_SESSION['groupRM']['sectorMapping']['matchedSector'] = 'Y';
        }
            
        $_SESSION['PREV_USERAGENT'] = $_SERVER['HTTP_USER_AGENT'];
        $_SESSION['PREV_REMOTEADDR'] = $_SERVER['REMOTE_ADDR'];
        $this->_OcorporateHomePageDetails->_Oconnection=$this->_Oconnection;
        #Set corporateId 1 when $_SESSION['groupRM']['airlinesCorporateId'] is !isset to fetch corporate_home_page_details
        $this->_OcorporateHomePageDetails->_IcorporateId= $_SESSION['groupRM']['airlinesCorporateId'] = isset($_SESSION['groupRM']['airlinesCorporateId']) ?
                $_SESSION['groupRM']['airlinesCorporateId'] : 1;
        $this->_OcorporateHomePageDetails->_SlandingStatus="AL";
        $CFG['mainPage']=$this->_OcorporateHomePageDetails->_selectCorporateHomePageDetails();

        if($this->_OcorporateHomePageDetails->_IcountLoop>0){
            $_SESSION['groupRM']['headerTpl']=$CFG['mainPage'][0]['header_tpl_name'];
            $_SESSION['groupRM']['footerTpl']=$CFG['mainPage'][0]['footer_tpl_name'];
        }
        else{
            #Set default header and footer name when $_SESSION['groupRM']['airlinesCorporateId'] is !isset
            $CFG['mainPage'][0]['header_tpl_name']="userHeader.tpl";
            $CFG['mainPage'][0]['footer_tpl_name']="userFooter.tpl";
            $_SESSION['groupRM']['headerTpl']=$CFG['mainPage'][0]['header_tpl_name'];
            $_SESSION['groupRM']['footerTpl']=$CFG['mainPage'][0]['footer_tpl_name'];
        }
        /*Set the session values for OAC details drop down*/
        if($this->_SapiLogin == 'Y')
        {
            $_SESSION['groupRM']['userName']=$this->_IinputData['userName'];
            $_SESSION['groupRM']['OAC']=$corporateDetailsArray[0]['pcc_code'];
            $_SESSION['groupRM']['OACDetails']=$this->_IinputData['OACDetails'];
            $_SESSION['groupRM']['OACResponse']=$this->_IinputData['OACResponse'];
        }
    }


    protected function _getUserLevelSettings(){
		fileRequire("classes/class.configLoad.php");
		$this->_objConfigLoad=new configLoad();
		$this->_objConfigLoad->_Oconnection=$this->_Oconnection;
		$settings=$this->_objConfigLoad->_getUserLevelSettingsFromDb();		
		$_SESSION['groupRM'] = array_merge($_SESSION['groupRM'],$settings);
    }
    

    protected function _getSiteCurrencyType(){
		$sql = "SELECT currency_type FROM currency_details WHERE exchange_rate=1 and currency_status='Y'";
        $result=$this->_Oconnection->query($sql);
		if(DB::isError($result))
		{
			fileWrite($sql,"SqlError","a+");
			return FALSE;
		}
		$row=$result->fetchRow(DB_FETCHMODE_ASSOC);
		$_SESSION['groupRM']['currencyType'] = $row['currency_type'];
		return $_SESSION['groupRM']['currencyType'];
    }



    protected function _getCorporateGroupId(){
		global $CFG;
		$sql="select
				corporate_type_id,
				".encrypt::_decrypt('corporate_name')." AS corporate_name,
				".encrypt::_decrypt('pos_code')." AS pos_code
			from
				".$CFG['db']['tbl']['corporate_details']."
			where
				corporate_id='".$_SESSION['groupRM']['groupCorporateId']."' ";
        $result=$this->_Oconnection->query($sql);
		if(DB::isError($result))
		{
			$this->_OobjResponse->call("commonObj.showErrorMessage","System down. Contact administrator.");
			fileWrite($sql,'SqlError','a+');
			return false;
		}
		$row = $result->fetchRow(DB_FETCHMODE_ASSOC);
		$_SESSION['groupRM']['groupUserTypeId']=$row['corporate_type_id'];
		//$_SESSION['groupRM']['groupUserPos']=$row['pos_code'];
		$_SESSION['groupRM']['groupCorporateName']=$row['corporate_name'];
		$CFG['corporate']=$row;
		return $CFG;
    }
    
    


	public function _checkCorporateStatus($corporateId){
		global $CFG;
		$sqlCheckCorporateActivation="SELECT
							corporate_status
					      FROM
							".$CFG['db']['tbl']['corporate_details']."
					      WHERE
							corporate_id=".$corporateId;

        $resultCheckCorporateActivation=$this->_Oconnection->query($sqlCheckCorporateActivation);
        if (DB::isError($resultCheckCorporateActivation)) {
            fileWrite($sqlCheckCorporateActivation, "SqlError", "a+");
            return FALSE;
        }
        
        if($resultCheckCorporateActivation->numRows() <= 0)
            return FALSE;
        $rowCheckCorporateActivation=$resultCheckCorporateActivation->fetchRow(DB_FETCHMODE_ASSOC);
        $corporateStatus=$rowCheckCorporateActivation['corporate_status'];
        return ($corporateStatus=="Y");
    }
    
    /**
     * function checkBlockIP
     * add blacklisted ip based on login count
     * 
     * @return bool
     */
    protected function _checkBlockIP(){
        if($_SESSION['groupRM']['loginCount'] <= systemSetup::_getGlobalConfig("login,ipVerificationCount")){
            return false;
        }

        $loginVerification = function(){
            return (new loginVerification())->setConnection($this->_Oconnection)
                ->setIpAddress($_SERVER['REMOTE_ADDR'])
                ->setEmailId($this->_IinputData['loginUserName'])
                ->setVerificationStatus('IB')
                ->setRequestedDate(date("Y-m-d H:i:s"));
        };
        
        if(count($loginVerification()->_selectLoginVerification()) <= 0){
            $server = json_encode($_SERVER); $session = json_encode($_SESSION);
            fileWrite("IP-Block: \nServer: $server \nSession: $session","securityErrors","a+");
            $loginVerification()->_insertLoginVerification();
        }
        
        session_destroy();
        //In SSO flow OobjResponse won't be available by kavi
        ($this->_OobjResponse!='') &&
            $this->_OobjResponse->script('setTimeout(\'window.location.replace("./")\',500);');

        return true;
    }
    

}






/**
 * class authenticate
 * 
 * @author Gopinath v <gopinath@infinitisoftware.net>
 */
class authenticate extends authHelper{

    public function __construct(){
        parent::__construct();        
    }

    /**
     * function _login
     * 
     * @return string interface - login constant
     */
    public function _login(){
        global $CFG;
        $result = $userCount = null;

        if($this->_IinputData['usernameLogin'] != 'Y')
            $this->_IinputData['loginUserName'] = strtolower(trim($this->_IinputData['loginUserName']));


        /* travel agent restriction */
        if(systemSetup::_getGlobalConfig('site,TALoginRestriction') =='Y'
                && $this->_checkTravelAgentRestriction()){
            return login::TARESTRICTION;
        }
        
        /*Ristricted groups for direct login in sso flow*/        
        if(systemSetup::_getGlobalConfig('site,sso,status') =='Y' 
                && $this->_SssoLoginCheck!="Y"
                && $this->_checkSSORestriction()){
            return login::SSOLOGIN;
        }
        /*Restrict groups for direct login in API*/
        if(systemSetup::_getGlobalConfig('site,apiLogin,status') =='Y'
            && $this->_SapiLogin != "Y" 
            && $this->_checkAPIRestriction()){
                return login::APILOGIN;
            }

        authHelper::resetUserDetails()->setConnection($this->_Oconnection)
            ->setEmailId($this->_IinputData['loginUserName']);

        if($CFG['login']['validateCountFromDB'] == 'Y')
            $this->_validateLoginCount();

        if(empty($_SESSION['groupRM']['deepLink']['status']))
        {
            /* captcha must be present if the loginCount is greater than captchaVerificationcount */
            if( $_SESSION['groupRM']['loginCount']>=systemSetup::_getGlobalConfig("login,captchaVeficationCount")
                && empty($this->_IinputData['captchaCode']) && $this->_SssoLoginCheck!="Y"){
            $this->_OobjResponse->script("document.getElementById('captchaDiv').style.display='block'");
            return login::CAPTCHAREQUIRED;
            }
            
            /* captcha */
            if(!$this->_checkCaptcha()){
                return captchaVerify::WRONGCAPTCHA;
            }
        }
        /*Assign apiLogin this variable to passwordBcrypt class object*/
        if($this->_SapiLogin == 'Y')
        {
            $this->passwordBCrypt->_SapiLogin = 'Y';
        }
        /* pwd */
        switch($this->passwordBCrypt->_getUserPwdType($this->_IinputData['loginUserName'])){
            case passwordBCrypt::PWD_MD5:
                $result = $this->_checkMD5();
                break;
            case passwordBCrypt::PWD_BCRYPT:
                $result = $this->_checkBCRYPT();
                break;
            default:
                throw new Exception("Password Type cannot be handled");
        }
        $CFG['user'] = isset($result[0]) ? $result[0] : [];
        $userCount =  isset($result[1])? $result[1]: 0;

        /* agencyTopup */
        $this->_setAgencyTopUp($userCount);

        /* username and pwd not valid */
        if($userCount<=0)
            return $this->_notValidUserFlow();

        /* check corporate status */
        if(!$this->_checkCorporateStatus($CFG['user'][0]['corporate_id']))
            return login::CORPORATE;

        
        if(isset($CFG['site']['apiLogin']['version']) && strtoupper($CFG['site']['apiLogin']['version']) == strtoupper('apiLoginV2') && $this->_SapiLogin != 'Y'){
            if(!$this->_checkDirectLoginAcess())
                return login::DIRECT_LOGIN_RESTRICTION;
        }

        if(systemSetup::_getGlobalConfig("security,session,concurrency") == "N"
                && systemSetup::_getGlobalConfig("security,session,loginconfirm") == "Y"
                && $this->_ObjSecurity->_accountAlreadyActive($CFG['user'][0]['user_id']) ){

            $username =  $this->_IinputData['loginUserName'];
            if($this->_IinputData['loginConfirm'] != "Y") {
                fileWrite("option to override :$username", 'securityErrors', 'a+');
                return login::ACCOUNT_ALREADY_ACTIVE;
             } elseif($this->_IinputData['loginConfirm'] == "Y") {
                /* log the user for which the override is happening */
                fileWrite("override session for user :$username", 'securityErrors', 'a+');
             }
        }            
        //If corporate type id is not set
        if(!isset($CFG['corporate'][0]['corporate_type_id']))
        {
            $_SESSION['groupRM']['groupCorporateId']= $CFG['user'][0]['corporate_id'];
            $this->_getCorporateGroupId();
        }
         /*Registration payment*/
        if($CFG['registration']['payment']['status'] == 'Y' && in_array($CFG['corporate']['corporate_type_id'], $CFG['registration']['payment']['corporateTypeId']) && !in_array($CFG['user'][0]['group_id'], $CFG['registration']['payment']['paymentUserGroupId']))
        {
            fileRequire("classesTpl/class.tpl.registrationPayment.php");
            $this->_OregistrationPaymentTpl = new registrationPaymentTpl();
            $this->_OregistrationPaymentTpl->_Oconnection = $this->_Oconnection;
            $_AregistrationPayment= $this->_OregistrationPaymentTpl->_getRegistrationPaymentDetails();
            if(!empty($_AregistrationPayment))
                return login::REGISTRATIONPAYMENT;
        }
        
        /*change session id after login */
        $this->_regenrateSessionId();

        /* insert values into sessionDetails */
        $this->_ObjSecurity->_insertSession(
            $CFG['user'][0]['user_id'],
            $_SESSION['groupRM']['userLoginTime']=date("Y-m-d H:i:s")
        );
        
        /* check config status and upgrade pwd */
        $this->_upgradeUserPwd();

        $this->_OcorporateDetails->_IcorporateId=$CFG['user'][0]['corporate_id'];
        /* set session values */
        $this->_setSessionValues($this->_OcorporateDetails->_selectCorporateDetails());

        if(isset($this->_IinputData['codelogin']) && $this->_IinputData['codelogin'] == 'Y'
        && $this->_IinputData['loginSecurityCode'] == ''&& $CFG['login']['MFA']['enable'] == 'Y' && !in_array($_SESSION['groupRM']['groupId'],$CFG['login']['MFA']['excludedgroupId'] ))
            return login::LOGINCODE;  
        
        if(isset($this->_IinputData['OTP']) && $this->_IinputData['OTP'] != '' && !in_array($_SESSION['groupRM']['groupId'],$CFG['login']['MFIS']['groupId'])) 
        {   
            fileRequire('classes/class.otp.php');
            $_OotpObj = new OTP();
            $_OotpObj->_setDb($this->_Oconnection);
            $_OotpObj->_setCommonObjConnection();
            $_OotpObj->_setSmarty($this->_Osmarty);

            /* 
            * Due to multiple hits on the link when the user comes from the Outlook mail
            * setting the user id from the deep link session if empty and security token by the user id 
            */

            $_IuserId = $_SESSION['groupRM']['otp']['userId'] ?? $_SESSION['groupRM']['deepLink']['userId'];
            $_SESSION['SecurityCode'] = $_SESSION['SecurityCode'] ?? $_OotpObj->_getResetTokenIdByUserId($_IuserId);

            $_checkResult = $_OotpObj->_verifyOTP($_IuserId, $this->_IinputData['OTP']);

            if($_checkResult === FALSE) {                
                return login:: CODENOTACCEPTED;
            } else {
                $this->_updateResetPassword();
            }
        }
        
        /* write actionlog */
        $this->_setLanguageWriteActionLog();

        //update last login details
        authHelper::resetUserDetails()->setConnection($this->_Oconnection)
                ->setUserId($CFG['user'][0]['user_id'])
                ->setLastLoginIpAddress($_SERVER['REMOTE_ADDR'])
                ->setLastLoginDate($this->_Ocommon->_getUTCDateValue())
                ->_updateUserDetails();


        return login::LOGINOK;
    }

    private function _regenrateSessionId(){
        session_regenerate_id(true);
        $this->_Ocommon->_setCookie(session_name(),session_id());
    }

    private function _checkTravelAgentRestriction(){
        authHelper::resetUserDetails()->setConnection($this->_Oconnection)
            ->setEmailId($this->_IinputData['loginUserName'])
            ->_selectUserDetails();
        return (authHelper::getUserDetails()->_IcountLoop>0) 
            && (authenticate::getUserDetails()->_IgroupId==11);
    }


    private function _checkSSORestriction(){
        authHelper::resetUserDetails()->setConnection($this->_Oconnection)
                        ->setEmailId($this->_IinputData['loginUserName'])
                        ->_selectUserDetails();
        
        return (authHelper::getUserDetails()->_IcountLoop>0)
            &&  in_array(
                    authenticate::getUserDetails()->_IgroupId,
                    systemSetup::_getGlobalConfig('site,sso,loginGroups')
                )
            && !in_array(
                    authenticate::getUserDetails()->_IuserId,
                    systemSetup::_getGlobalConfig('site,sso,skipUsers')
                );
    }

    /**
     * function _upgradeUserPwd
     * upgraddes user pwd from md5 to bcrypt
     * 
     * @throws Exception - can not insert into userPwdMapping
     * @throws Exception - can not insert into pwd_upgrade
     * @return boolean
     */
    private function _upgradeUserPwd(){
        global $CFG; $pwdHash = null;
        if(!$this->passwordBCrypt->_isPassUpgradeRequirements() ||
                !$this->passwordBCrypt->_isPassRequirements())
            return;
        
        $insertStatus = (new userPasswordMapping())->setConnection($this->_Oconnection)
                            ->setUserId($CFG['user'][0]['user_id'])
                            ->setLastUpdatedPassword($CFG['user'][0]['user_password'])
                            ->_insertUserPasswordMapping();
        if(!$insertStatus)
            throw new Exception("can not insert into userPwdMapping");
        
        /* insert into pwd table */
        $pwdHash = encrypt::_generateHash($this->_IinputData['loginUserPassword']);
        $_AresultToken =  $this->_Oconnection->_performQuery(
                                $CFG['db']['tbl']['pwd_upgrade'],
                                [   
                                    'pwd_upgrade_id' => 0, 'user_id' => $CFG['user'][0]['user_id'],
                                    'old_pwd' => $CFG['user'][0]['user_password'], 'new_pwd' => $pwdHash
                                ],
                                'DB_AUTOQUERY_INSERT'
                            );
        if(!$_AresultToken)
            throw new Exception("can not insert into pwd_upgrade");

        $updateStatus = authHelper::resetUserDetails()
                            ->setConnection($this->_Oconnection)
                            ->setUserId($CFG['user'][0]['user_id'])
                          //  ->setUserPassword($pwdHash)
                            ->_updateUserDetails();
        return $updateStatus;
    }






    /**
     * _notValidUserFlow
     * unverified emailId, unapproved, email pwd mismatch flow.
     * 
     * @return mixed
     */
    protected function _notValidUserFlow(){

        // check and block ip, destroy session and return,
        if($this->_checkBlockIP()){
            return false;
        }
        // check and  block account
        $this->checkBlockAccount();

        //In SSO flow OobjResponse won't be available by kavi
        if($this->_OobjResponse!='')
        {
            $_SESSION['groupRM']['loginCount'] = $_SESSION['groupRM']['loginCount']+1;
            if($_SESSION['groupRM']['loginCount'] >= systemSetup::_getGlobalConfig("login,captchaVeficationCount")){
                $this->_OobjResponse->script("document.getElementById('captchaDiv').style.display='block'");
            }
            $this->_OobjResponse->script("loginVerification++");
        }

        fileRequire("dataModels/class.loginVerification.php");
        $loginVerification = (new loginVerification())->setConnection($this->_Oconnection)
                        ->setEmailId($this->_IinputData['loginUserName'])
                        ->_selectLoginVerification();
        
        $userDetails = authHelper::resetUserDetails()
            ->setConnection($this->_Oconnection)
            ->setEmailId($this->_IinputData['loginUserName'])
            ->_selectUserDetails();

        if(authHelper::getUserDetails()->_IcountLoop <= 0){
            /* email not valid */
            return login::EMAIL;
        }
        
    
        $password=$userDetails[0]['user_password'];
        $approvedStatus=$userDetails[0]['approved_status'];
        $emailVerificationStatus=$userDetails[0]['email_verification_status'];
        $corporateId=$userDetails[0]['corporate_id'];
        /* email not verified */
        if(strtoupper($emailVerificationStatus)!="Y"){
            return login::EMAILVERIFY;
        }   
            
        /* account blocked */
        if(strtoupper($approvedStatus)!="Y" 
                && !empty($loginVerification)
                && strtoupper($loginVerification[0]['verification_status'])=='AB'){

            return login::ACCOUNTBLOCK;
        }

        /* account not approved */
        if(strtoupper($approvedStatus)!="Y")
            return login::APPROVAL;

        $passwordMatch = false;
        /* check pwd is md5 (column property, md5 property(alphanumeric,and length 32)) */
        if($this->_Ocommon->_checkHashIsMD5($password))
            $passwordMatch = ($this->_Ocommon->md5valueEncoder($this->_IinputData['loginUserPassword'])==$password);
        else 	/* upgraded pwd hash verify */
            $passwordMatch = encrypt::_verifyHash($this->_IinputData['loginUserPassword'], $password);
        
        /* pwd is wrong */
        if(!$passwordMatch)
            return login::PASSWORD;

        /*	update pwd non verififed accounts, if that too contains md5 pwd. */
        $this->_upgradeUserPwd();
    
        /* account not approved */
        if(strtoupper($approvedStatus)!="Y")
            return login::APPROVAL;
        /* email verification status */
        if(strtoupper($emailVerificationStatus)!="Y" && (isset($this->_IinputData['fromInstant']) && $this->_IinputData['fromInstant'] != 'Y'))
            return login::EMAILVERIFY;
        /* corporate status */
        return ($this->_checkCorporateStatus($corporateId)) ? login::LOGINOK: login::CORPORATE;
    }


    /**
     * function blockAccount
     * blocks account 
     * @return bool
     */
    private function checkBlockAccount(){
        if($_SESSION['groupRM']['loginCount'] <= systemSetup::_getGlobalConfig("login,userVerificationCount")){
            return false;
        }

        // check account exists
        $user = authHelper::resetUserDetails()
                    ->setConnection($this->_Oconnection)
                    ->setEmailId($this->_IinputData['loginUserName'])           
                    ->_selectUserDetails();
        if(empty($user)){
            return false;
        }

        // check already row is present
        $loginVerification = (new loginVerification())->setConnection($this->_Oconnection)
                ->setIpAddress($_SERVER['REMOTE_ADDR'])
                ->setEmailId($this->_IinputData['loginUserName'])
                ->setVerificationStatus('AB');
        
        // insert loginVerification
        if(count($loginVerification->_selectLoginVerification()) <= 0){
            $server = json_encode($_SERVER); $session = json_encode($_SESSION);
            fileWrite("Account-Block: \nServer: $server \nSession: $session","securityErrors","a+");
            $loginVerification->setRequestedDate(date("Y-m-d H:i:s"))
                ->_insertLoginVerification();
        }
               

        // update userdetails with approved status to N
        if(authHelper::getUserDetails()->_IcountLoop > 0 && $user[0]['approved_status'] != 'N'){
            ($userJson = json_encode($user)) 
                && fileWrite("Account-Block: \nApprovedStatus to 'N' \n$userJson", "securityErrors","a+");
            authHelper::resetUserDetails()
                    ->setConnection($this->_Oconnection)
                    ->setUserId($user[0]['user_id'])->setEmailId($this->_IinputData['loginUserName'])
                    ->setApprovedStatus('N')
                    ->_updateUserDetails();
        }
        return true;   
    }





    /**
     * function _checkMD5
     *
     * @author Gopinath v <gopinath@infinitisoftware.net>
     * @return array - [userdetailsArray, userCountSelected]
     */
    protected function _checkMD5(){
        $userPwd = null;
        /* agency topup login or sso login check passes hashed pwd instead of plaintext*/
        $userPwd = ($this->_OagencyTopupLoginCheck=='Y'||$this->_SssoLoginCheck=="Y"||$this->_SapiLogin=="Y" || $_SESSION['groupRM']['deepLink']['status'] == 'Y' || $_SESSION['groupRM']['makePaymentLink'] == 'Y')? $this->_IinputData['loginUserPassword'] 
                        : $this->_Ocommon->md5valueEncoder($this->_IinputData['loginUserPassword']);
        //fileWrite(print_r($this->_IinputData['fromInstant'],1),'inputData','a+');
        if(isset($this->_IinputData['checkEmailVerification']) && $this->_IinputData['checkEmailVerification'] == 'Y')  {
            $_SemailVerificationStaus = (isset($this->_IinputData['fromInstant']) && $this->_IinputData['fromInstant'] == 'Y') ? 'N' : 'Y';
        }
        else 
            $_SemailVerificationStaus = 'Y';

        $setUserName = "setEmailId";
        if($this->_IinputData['usernameLogin'] == 'Y')
            $setUserName = "setUsername";


        fileWrite($_SemailVerificationStaus,'_SemailVerificationStaus','a+');
        return [
                    authHelper::resetUserDetails()
                        ->setConnection($this->_Oconnection)
                        ->$setUserName($this->_IinputData['loginUserName'])
                    //    ->setUserPassword($userPwd)                        
                        ->setEmailVerificationStatus($_SemailVerificationStaus)
                        ->setApprovedStatus('Y')
                        ->_selectUserDetails(),
                    authHelper::getUserDetails()->_IcountLoop
                ];
    }





    /**
     * function _checkBCRYPT
     * 
     * @author Gopinath v <gopinath@infinitisoftware.net>
     * @return array [ userdetailsArray , userCountSelected] 
     */
    protected function _checkBCRYPT(){
        if($this->passwordBCrypt->_getUserPwdType($this->_IinputData['loginUserName']) ==
                passwordBCrypt::PWD_MD5)
            return $this->_checkMD5();

        $setUserName = "setEmailId";
        if($this->_IinputData['usernameLogin'] == 'Y')
            $setUserName = "setUsername";

        $userDetails = authHelper::resetUserDetails()
                            ->setConnection($this->_Oconnection)
                            ->setApprovedStatus('Y')
                            ->setEmailVerificationStatus('Y')
                            ->$setUserName($this->_IinputData['loginUserName'])
                            ->_selectUserDetails();
                            
		/* check db-pwd and userEntered-pwd */
        if(!encrypt::_verifyHash($this->_IinputData['loginUserPassword'], $userDetails[0]['user_password']) ){
            return [[], 0];  /* empty user if hash does not match */
        }

        return [$userDetails, authHelper::getUserDetails()->_IcountLoop];
    }






    /**
     * function _checkCaptcha
     * verify captcha based on logincount 
     * 
     * @param boolean $checkSession
     * @return boolean
     */
    public function _checkCaptcha(){
        global $CFG;

        if($_SESSION['groupRM']['loginCount']>=$CFG['login']['captchaVeficationCount']
            && $CFG['site']['loginCaptcha'])
        {
    		fileRequire("classes/class.userOperations.php");
    		$this->_OuserOperations = new userOperations();
            $this->_OuserOperations->_IinputData  = $this->_IinputData; 
            $this->_OuserOperations->_OobjResponse = $this->_OobjResponse;
            $this->_OuserOperations->_Osmarty = $this->_Osmarty;

            if(!$this->_OuserOperations->_validateCAPTCHA('L')){
                $_SESSION['groupRM']['loginCount']=$_SESSION['groupRM']['loginCount']+1;
                $this->_checkBlockIP();
                $this->checkBlockAccount();
                return false;
            }
           
        }
        
        return true;
        }   






    /**
     * function _setLanguageWriteActionLog
     *
     * @return void
     */
    protected function _setLanguageWriteActionLog(){
        global $CFG;
        if(!in_array($_SESSION['groupRM']['groupId'],$CFG['default']['airlinesGroupId']))
            return;
        unset($_COOKIE['groupRMLan']);
        #To check language process
        fileRequire("classes/class.systemSetup.php");
        if(!empty($CFG["groupRM"]["siteLang"]['adminLang']))
            $CFG["groupRM"]["siteLang"]['defaultLang']=$CFG["groupRM"]["siteLang"]['adminLang'];
        $this->_ObjSecurity->_setLanguage();
        #Write group action query file for each module action.
        $this->_ObjSecurity->_actionLog();
    }





    /**
     * function setAgencyTopup
     *
     * @param [type] $userCount
     * @return void
     */
    protected function _setAgencyTopup($userCount){
        global $CFG;
        if(in_array($CFG['default']['airlineCode'],$CFG['site']['agencyTopUpAccess']) &&
                $userCount == 0){
        authHelper::getUserDetails()->setApprovedStatus('N')
                            ->_selectUserDetails();
            if(authHelper::getUserDetails()->_IcountLoop > 0){
                fileRequire("classes/class.getUserDetailsService.php");
                $this->_OgetUserDetailsService = new getUserDetailsService();
                $this->_OgetUserDetailsService->_Oconnection = $this->_Oconnection;
                /*checking the user is having the agency top access or not*/
                if($this->_OgetUserDetailsService->_getAgencyTopUpAccess(authHelper::getUserDetails()->_IuserId)){
                    $CFG['user']=authHelper::getUserDetails()->_AuserDetails;
                    $_SESSION['groupRM']['agencyTopup'] = 'Y';
                }
                
            }
            if(empty($CFG['user']))
                authHelper::resetUserDetails();
        } 
    }





    public function _checkPasswordExpiry(){
        global $CFG;
        $this->_IinputData['loginUserName'] = strtolower(trim($this->_IinputData['loginUserName']));
        $userDetailsResult = authHelper::resetUserDetails()
                                    ->setConnection($this->_Oconnection)
                                    ->setEmailId($this->_IinputData['loginUserName'])
                                    ->_selectUserDetails()[0];
		
		$OldPwdStatus  = ($this->_Ocommon->_getGlobalConfig("password,passwordUpgrade")!="Y")
						      && ($this->_Ocommon->_checkHashIsMD5($userDetailsResult['user_password']) );
		//Start of pwd expiry if old pwd is used
		if($OldPwdStatus){
            $validationsql="SELECT
                            user_id,
                            group_id
                        FROM
                            ".$CFG['db']['tbl']['user_details']."
                        WHERE
                            ".encrypt::_decrypt('email_id')."='".$this->_IinputData['loginUserName']."' AND
                            user_password='".$this->_Ocommon->md5valueEncoder($this->_IinputData['loginUserPassword'])."'";
		} else {
			$validationsql="SELECT
							user_id,
							group_id
						FROM
							".$CFG['db']['tbl']['user_details']."
						WHERE
							".encrypt::_decrypt('email_id')."='".$this->_IinputData['loginUserName']."' AND
							user_password='".$userDetailsResult['user_password']."'";	
		}
		
		//wiithout password select	
		$this->_Ocommon->_Oconnection = $this->_Oconnection;
        $validationQry = $this->_Ocommon->_executeQuery($validationsql);
        $this->setPasswordExpiryUID($validationQry[0]['user_id']);
		if(!empty($validationQry) && $validationQry[0]['group_id'] > 0 && in_array($validationQry[0]['group_id'], $CFG['settings']['checkGroupidPasswordExpiry']))
		{
			//password expiry verification
			$validationcheck = $this->_Ocommon->_checkOldPassword($validationQry[0]['user_id'],$this->_Ocommon->md5valueEncoder($this->_IinputData['loginUserPassword']),$CFG['settings']['passwordConsecutiveCheck']);
			if($validationcheck == "N" || $this->_Ocommon->_SmatchLastPassword == "N"){
				unset($_SESSION['groupRM']);
				return PwdExpiry::PASSWORDCHANGE;
			}
			//password expiry date verification
			$pwdexpiryDays = $this->_Ocommon->_getPasswordExpiryDays($validationQry[0]['user_id'], $this->_Ocommon->_DlastUpdatedDate);
			if($pwdexpiryDays > $CFG['settings']['passwordExpiry']){
				unset($_SESSION['groupRM']);
				return pwdExpiry::PASSWORDEXPIRYVALIDATION;
			}
		}
		return PwdExpiry::PWDEXPIRYOK;
        //End of pwd expiry
    }

    /*Function name : _checkAPIRestriction()
     *Description   : This function used to restrict group id for API login
     *Parameter     : NULL            
     *Return        : (BOOLEAN)
     *Created date  : 29-07-2021
     *Author        : Roja.G
     * */
    public function _checkAPIRestriction(){
        authHelper::resetUserDetails()->setConnection($this->_Oconnection)
                        ->setEmailId($this->_IinputData['loginUserName'])
                        ->_selectUserDetails();
        $userNameCheckFlag = TRUE;

        if(systemSetup::_getGlobalConfig('site,apiLogin,restrictUserName') == 'Y')
        {
            $userNameCheckFlag = authenticate::getUserDetails()->_SuserName != NULL ; 
        }
        return (authHelper::getUserDetails()->_IcountLoop>0)
            &&  in_array(
                    authenticate::getUserDetails()->_IgroupId,
                    systemSetup::_getGlobalConfig('site,apiLogin,loginGroups')
                )
            && !in_array(
                    authenticate::getUserDetails()->_IuserId,
                    systemSetup::_getGlobalConfig('site,apiLogin,skipUsers')
                )
            && $userNameCheckFlag;
    }

    public function _checkSecurityCode($_userId) {
        global $CFG;
        
        $validationsql="SELECT
							url_token,expiry_time
						FROM
							".$CFG['db']['tbl']['reset_password']."
						WHERE
							user_id ='".$_userId."' AND 
							reset_token_id ='".$_SESSION['SecurityCode']."'
                             AND used_status = 'N' AND reset_token_type = 'GC' limit 1";		
		//wiithout password select	
		$this->_Ocommon->_Oconnection = $this->_Oconnection;
        $_AcodeExist = $this->_Ocommon->_executeQuery($validationsql);

        if(!empty($_AcodeExist[0])) {
            $_SdecryptUrlToken = encrypt::_decode($_AcodeExist[0]['url_token']);
            fileWrite($_SdecryptUrlToken." == ".$this->_IinputData['loginSecurityCode']." -- ".$_userId,'code','a+');
            if($_AcodeExist[0]['expiry_time'] < date('Y-m-d H:i:s')) {
                $_SESSION['Codeexpirytime'] = $_AcodeExist[0]['expiry_time'];
                return false;
            } else if(strtoupper($_SdecryptUrlToken) != strtoupper($this->_IinputData['loginSecurityCode'])) {
                return false;
            } else 
                return true;
        } else {
            //$_SESSION['Codeexpirytime'] = $_AcodeExist[0]['expiry_time'];
            return false;
        }
    }

    //update reset password table from status 'N' to 'Y' if code is matched
    public function _updateResetPassword() {
        global $CFG;
        
        $successupdatesql="UPDATE 
        ".$CFG['db']['tbl']['reset_password']." SET used_status = 'Y'
        WHERE					
        reset_token_id ='".$_SESSION['SecurityCode']."' AND
        reset_token_type = 'GC' ";		
        fileWrite($successupdatesql,'successupdatesql','a+');
			
        if(DB::isError($_Oresult=$this->_Oconnection->query($successupdatesql)))
        {
            fileWrite($successupdatesql,'SqlError','a+');
            exit($successupdatesql);
        }  else {
            return true;
        }     
		
    }

       
    
    
    /**
     * function _validateLoginCount
     *
     * Discription: For Recording and validating the login count in login_verification table 
     * 
     * @return bool
     * 
     * @author Ajeesh T
     */
    public function _validateLoginCount() {

        global $CFG;

        $_AadditionalInfo = array();
        $_AadditionalInfo['useragent'] = $_SERVER['HTTP_USER_AGENT'];
        
        $loginVerification = (new loginVerification())->setConnection($this->_Oconnection)
            ->setIpAddress($_SERVER['REMOTE_ADDR'])
            ->setVerificationStatus('TB');
        
        $loginVerificationDetails = $loginVerification->_selectLoginVerification();
        
        // check if the user is already attempted to login
        if(count($loginVerificationDetails) > 0 ){

            if($this->_loginVerificationFromDb($loginVerificationDetails,$loginVerification)){
                return false;
            }
        }

        $_AadditionalInfo['attempt_count'] = 1;
        $_JadditionalInfo = json_encode($_AadditionalInfo);

        // insert new user into loginVerification with attempt_count as 1
        $loginVerification->setRequestedDate(date("Y-m-d H:i:s"))
            ->setAdditionalInfo($_JadditionalInfo)
            ->setEmailId($this->_IinputData['loginUserName'])
            ->setVerificationStatus('TB')
            ->_insertLoginVerification();

        return true;
    }
    
    /**
     * function _loginVerificationFromDb
     *
     * Description: For validating the session login count from login_verification table 
     * 
     * @param  mixed $loginVerificationDetails
     * @param  mixed $loginVerification
     * @return bool
     * 
     * @author Ajeesh T
     */
    function _loginVerificationFromDb($loginVerificationDetails,$loginVerification){
        
        foreach($loginVerificationDetails as $loginVerificationDetail){
                    
            $loginVerificationDetail['additional_info'] = json_decode($loginVerificationDetail['additional_info'],1);

            //If same useragent then increment the attempt_count
            if($loginVerificationDetail['additional_info']['useragent'] == $_SERVER['HTTP_USER_AGENT']) {

                $_AadditionalInfo = array();
                $_AadditionalInfo['useragent'] = $_SERVER['HTTP_USER_AGENT'];
                $_AadditionalInfo['attempt_count'] = $loginVerificationDetail['additional_info']['attempt_count'] + 1;
                $_JadditionalInfo = json_encode($_AadditionalInfo);

                //update the incremented attempt_count
                $loginVerification->setRequestedDate(date("Y-m-d H:i:s"))
                    ->setAdditionalInfo($_JadditionalInfo)
                    ->_updateLoginVerification();

                //override the session count from DB count
                if($_SESSION['groupRM']['loginCount'] < $loginVerificationDetail['additional_info']['attempt_count'])
                    $_SESSION['groupRM']['loginCount'] = $loginVerificationDetail['additional_info']['attempt_count'];

                return true;

            }
        }
    }
    
    /**
     * Function _checkDirectLoginAcess
     * Description: Check Direct Login Access for users when they try to login with email id while APILoginV2 is enabled
     * @return bool
     * @author Ajeesh
     */
    public function _checkDirectLoginAcess(){

        global $CFG;

        $jsonPath = 'xml/apiLoginV2.json';
        $_AapiLoginV2 = json_decode($this->_Ocommon->_loadJsonFile($jsonPath),true);
        if(in_array($CFG['user'][0]['group_id'],$_AapiLoginV2['directLoginGroups']) || in_array($CFG['user'][0]['user_id'],$_AapiLoginV2['allowInternalUsers']))
            return true;
        
        return false;
    
    }
}

?>
