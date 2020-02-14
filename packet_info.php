<?php

if(!isset($_SESSION)) session_start();

// Upated: 2020/02/14
// by Victor Yang
$version = '20200214';

require_once __DIR__.'/common.php';

###################### Global variables ######################

$packet_no = $_POST['packet_no'];
$file_info = $_POST['file_info'];
$packet_info = $_POST['packet_info']; # Apr 27, 2018 12:59:48.529061000 CST

# using nanosecod to work around SKE2
$packet_info = substr($packet_info, 0, strlen($packet_info) - 4); # Apr 27, 2018 12:59:48.529061000

$tree = Array();
$new_tree = Array();

//Start Time
$query_start = getmicrotime();

$decode_as = "";
$cmd = "tshark -Y '(frame.time==\"$packet_info\")' -d udp.port==5072,sip -r $file_info -t ad -P -V -x 2>&1";

if(file_exists($file_info)) {
	# 執行網頁網站本身的 wireshark，此作法能統一內容顯示
	$ret_val = shell_exec($cmd);
	$ret_arr = preg_split('/\n/',$ret_val);

	# packet summary:
	# 	1 2018-06-22 15:45:00.002701 172.28.129.32 → 172.28.72.65 SIP/ISUP(ITU) 947 Request: BYE sip:172.28.72.65 | , ISUP:REL
	#
	# packet tree:
	# 	Frame 1: 947 bytes on wire (7576 bits), 947 bytes captured (7576 bits)
	# 換行
	#
	# packet hex and ascii:
	# 	0000 00 00 5e 00 01 02 00 11 3f ce 65 dd 08 00 45 00 ..^.....?.e...E.
	$pkt_no = 0;
	$step = 0;
	$packet_summary = array(); // step 0
	$packet_tree = ""; // step 1
	$packet_hex = ""; // step 2
	$text = "";

	for($i=0, $j=0, $parent_id=0; $i<count($ret_arr)-1; $i++) {
		$arr1 = array(); // temp array
		# Regex to replace multiple spaces to single space excluding leading spaces
		#  1 2018-06-22 15:45:00.144345         4400 ? 2531         ISUP(ITU) 43 IAM (CIC 2888)
		$ret_arr[$i] = preg_replace('/\b\s+\b/',' ',$ret_arr[$i]); # for ISUP summary
		$arr1 = preg_split('/ /', trim($ret_arr[$i])); // strip whitespace from the beginning and end of a string
		if(!strcmp('Frame', $arr1[0]) && $step != 2) {
			$step = 1;
		} else if(!strlen($arr1[0]) && $step == 1) {
			$step = 2;
			$text .= '<hr><pre>';
		} else if(!strlen($arr1[0]) && $step == 2) {
			$text .= '</pre><hr>';
			$step = 3;
		}
		switch($step) {
			case 0:
				#
				# step 0: packet summary
				#  1 2018-06-22 15:45:00.002701 172.28.129.32 → 172.28.72.65 SIP/ISUP(ITU) 947 Request: BYE sip:172.28.72.65 | , ISUP:REL
				#  1 2018-06-22 15:45:00.144345         4400 ? 2531         ISUP(ITU) 43 IAM (CIC 2888)
				$packet_summary[$j]['id'] = array_shift($arr1);
				$packet_summary[$j]['pkt_time'] = array_shift($arr1).' '.array_shift($arr1);
				$packet_summary[$j]['ip_src'] = array_shift($arr1);
				array_shift($arr1);
				$packet_summary[$j]['ip_dst'] = array_shift($arr1);
				$packet_summary[$j]['protocol'] = array_shift($arr1);
				$packet_summary[$j]['size'] = array_shift($arr1);
				$packet_summary[$j]['pkt_info'] = htmlentities(join(' ',$arr1));
				$j++;
				break;

			case 1:
				#
				# step 1: packet tree
				# 	Frame 1: 947 bytes on wire (7576 bits), 947 bytes captured (7576 bits)

				# tree begin
				if(!strcmp('Frame', substr($ret_arr[$i],0,5))) {
					$text .= '<div id="btnfloat" class="form-group">';
					$text .= '<button type="button" class="btn btn-success" id="btn-expand-all">展開</button>&nbsp;';
					$text .= '<button type="button" class="btn btn-warning" id="btn-collapse-all">合併</button>';
					$text .= '</div>';
					$text .= '<div id="pkt_frame"></div>';
				}
				# 修正 xml tag
				$ret_arr[$i] = htmlspecialchars($ret_arr[$i]);
				# 比較目前的空白數與下一行的空白數，如果下一行的空白數比目前的多，應該為 folder
				# ps. 一組空白數為 4 的倍數
				$curr_space = strlen($ret_arr[$i]) - strlen(preg_replace('/^\s+/', '', $ret_arr[$i]));
				$next_space = strlen($ret_arr[$i+1]) - strlen(preg_replace('/^\s+/', '', $ret_arr[$i+1]));

				# debug
				#$ret_arr[$i] = $curr_space.' '.$next_space.' '.$ret_arr[$i];
				if($curr_space < $next_space) {
					# folder begin
					//$text .= '<li class="closed"><span class="folder">'.$ret_arr[$i].'</span><ul>';
					$sub_data["id"] = $i;
					$sub_data["text"] = $ret_arr[$i];
					$sub_data["parent_id"] = $parent_id;
					$parent_id = $i;
					$tree[] = $sub_data;
				} else if($curr_space == $next_space) {
					# file
					//$text .= '<li><span class="file">'.$ret_arr[$i].'</span></li>';
					$sub_data["id"] = $i;
					$sub_data["text"] = $ret_arr[$i];
					$sub_data["parent_id"] = $parent_id;
					$tree[] = $sub_data;
				} else {
					# file
					//$text .= '<li><span class="file">'.$ret_arr[$i].'</span></li>';
					$sub_data["id"] = $i;
					$sub_data["text"] = $ret_arr[$i];
					$sub_data["parent_id"] = $parent_id;
					$tree[] = $sub_data;
					# folder end
					$p = $i;
					for($k=$next_space; $k<$curr_space & $p > 1; $k+=4) {
						//$text .= '</ul></li>';
						$p = $tree[$p-1]["parent_id"];
						$parent_id = $tree[$p-1]["parent_id"];
						//krumo("$p $parent_id");
					}
				}
				break;

			case 2:
				$text .= htmlspecialchars($ret_arr[$i])."\n";
				break;

			case 3:
				$text .= '<font color=red>'.htmlspecialchars($ret_arr[$i])."</font>\n";
				break;
		}

	} // end...for($i=0; $i<$count($ret_arr)-1; $i++)
	$text .= '</pre>';

	# step 1:
	// Create Treeview with Bootstrap Treeview Ajax JQuery in PHP
	// https://www.youtube.com/watch?v=bNFe1c1Iy80
	//krumo($tree);
	foreach($tree as $key => &$value) {
		$data[$value["id"]] = &$value;
	}
	foreach($tree as $key => &$value) {
		if($value["parent_id"] && isset($data[$value["parent_id"]])) {
			$data[$value["parent_id"]]["nodes"][] = &$value;
		}
	}
	foreach($tree as $key => &$value) {
		if($value["parent_id"] && isset($data[$value["parent_id"]])) {
			//krumo($tree[$key]);
			unset($tree[$key]);
		}
	}
	foreach($tree as $key => &$value) {
		$new_tree[] = $tree[$key];
		unset($tree[$key]);
	}
	$show_page = $text;

} else {

	$show_page = "<font color=red>Request Error! (10)</font><p>".
	             "<font color=blue>Not found <?=$file_info?></font>";
} // end...if(file_exists($file_info))
?>
<!DOCTYPE html>
<html lang="zh-TW">
<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="description" content="Packet Info Page">
	<meta name="author" content="yaovct">

	<title>封包內容</title>

	<!-- Bootstrap -->
	<link href="css/bootstrap.min.css" rel="stylesheet">
	<link href="css/bootstrap-treeview.min.css" rel="stylesheet">
</head>
<body style='margin-top: 5px'>
<div class="wrapper">
	<div class="container col-sm-12 col-xs-12">
		<div id="pkt_toolbar">
<?php
  print '<font color=blue><strong>Flow No #'.$packet_no.'</strong></font>, ';
	if(!empty($spend_query_time)) {
		print '查詢：'.$spend_query_time." 秒；";
	} else {
		$spend_query_time = 0;
	}
	print "執行：".(round(getmicrotime() - $query_start - $spend_query_time,3))." 秒 ";
	print '<font color=lightgrey>'.$file_info.' / '.$packet_info.'</font><p>';


?>
		</div><!-- /.content -->
	</div>
	<div class="container col-sm-12 col-xs-12">
	<?php echo $show_page; ?>
	</div><!-- /.container -->
</div><!-- /.wrapper -->
<script src="js/jquery-3.4.1.min.js"></script>
<script src="js/bootstrap-treeview.min.js"></script>
<script>
/***** 畫面完成 *****/

//$(document).ready(function() {
$(function() {

	var tree = <?php print json_encode($new_tree,JSON_HEX_QUOT | JSON_HEX_TAG); ?>;

	$('#pkt_frame').treeview({
		color: "#428bca",
		data: tree
	});
	$('#pkt_frame').treeview('collapseAll', { silent: true });

	$('#btn-expand-all').on('click', function (e) {
		var levels = $('#select-expand-all-levels').val();
		$('#pkt_frame').treeview('expandAll', { silent: false });
	});
	$('#btn-collapse-all').on('click', function (e) {
		$('#pkt_frame').treeview('collapseAll', { silent: true });
	});

});

</script>
</body>
</html>
