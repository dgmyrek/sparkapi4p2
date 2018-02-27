
<?php
class SparkAPI_Bearer extends SparkAPI_OAuth implements SparkAPI_AuthInterface {
	function __construct($access_token) {
		parent::__construct(null, null, null, $access_token);
	}
}