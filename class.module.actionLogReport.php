<?php
/*
 * @class		   actionLogReport 
 * @author         Ganesan
 * @created date   2017-10-09	
 */
fileRequire("classesTpl/class.tpl.baseModule.php");
class actionLogReport extends baseModule
{
	public $_Osmarty = '';

	public $_OobjResponse = '';

	public $_Oconnection = '';

	public $_OtplObj;

	public $_IinputData = [];

	public function __construct()
	{
		parent::__construct();
	}

	public function _setModuleData(): void
	{
		for ($this->_IloopCount = 0; $this->_IloopCount < count((array)$this->_StemplateType); $this->_IloopCount++)
		{
			if($this->_classTplName[$this->_IloopCount] == 'class.tpl.groupActionReportTpl')
			{
				fileRequire("classesTpl/class.tpl.groupActionReportTpl.php");
				$this->_OtplObj = new groupActionReportTpl();
				$this->_setSampleModule();
			}
		}
	}

	public function _setSampleModule(): void
	{
		$this->_OtplObj->_Osmarty = $this->_Osmarty;
		$this->_OtplObj->_Oconnection = $this->_Oconnection;
		$this->_OtplObj->_OobjResponse = $this->_OobjResponse;
		$this->_OtplObj->_IinputData = $this->_IinputData;
		/* 
		 * Using one class module file to perform action in different
		 * template.
		 */ 
		$functionName = "_".$this->_SmoduleName;
		$this->_OtplObj->$functionName();
		if ($this->_IinputData['exportData'] == 'Y')
		{
			$this->_OtplObj->_exportActionData();
		}

		if (isset($this->_IinputData['pageNo']))
		{
			$this->_SdivName = "";
			$this->_StemplateNameArray = ['empty.tpl'];
		}

		if (!isset($this->_IinputData['pageNo'])) 
			$this->_OtplObj->_displayModuleDetails();

	}
}	
?>
