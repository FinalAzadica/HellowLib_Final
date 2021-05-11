
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "pos_crypto.h"
#include "demo.h"

char print_buf[1024] = {0};

static int demo_init();

int hex_string_to_bytes(
	char* hex_string, 
	int hex_string_len, 
	unsigned char* bytes, 
	int bytes_len);
char* bytes_to_hex_string(
	char* print_buf, 
	int print_buf_len, 
	const unsigned char* bytes, 
	int len);

unsigned char hex_of_char(char c);

static void print_info_response(INFO_RESPONSE *response);
/**
 * 验证二维码例程
 *
 * 本例程演示了如何使用支付宝离线安全库对二维码进行验证
 * 
 * */
void check_qrcode_demo(){

	int ret = 0;
	
	unsigned char qrcode[512] = {0};
	int qrcode_len = sizeof(qrcode);
	/*
	* info_response mot
	*/
	char cert_sn[7] = {0};
	char mot_code_issuer_no[9] = {0};
	char card_issuer_no[9] = {0};
	char mot_user_id[17] = {0};
	char mot_card_no[21] = {0};
	unsigned char mot_card_data[129] = {0};
	/*
	* info_response alipay
	*/
	char alipay_code_issuer_no[9] = {0};
	char card_type[9] = {0};
	char alipay_user_id[17] = {0};
	char alipay_card_no[20] = {0};
	unsigned char alipay_card_data[129] = {0};

	char proto_type[8] = {0};

	INFO_REQUEST info_request;
	INFO_RESPONSE info_response;
	CODE_INFO code_info;
	info_response.code_info = &code_info;

	char qrcode_hex[] = QRCODE_HEX_DATA;
	int qrcode_hex_len = strlen(qrcode_hex);

	hex_string_to_bytes(qrcode_hex, qrcode_hex_len, qrcode, qrcode_len);

	printf("===========准备数据================\n");
	
	printf("============进行POS初始化=============\n");	
	/**
	 * 请在POS启动时执行POS初始化
	 * 初始化时请提供初始化信息，见 INIT_REQUEST
	 */
	ret = demo_init();
	if(ret != SUCCESS){
		printf("初始化POS失败！\n");
		switch(ret){
			case ILLEGAL_PARAM:
				printf("初始化参数格式错误！请检查参数各字段是否正确。\n");
			break;
			case NO_ENOUGH_MEMORY:
				printf("内存不足，极端错误，请检查程序运行空间是否足够。\n");
			break;
			case SYSTEM_ERROR:
				printf("系统异常！请联系支付宝技术人员。\n");
			break;
			default:
			break;
		}
		return;
	}

	/**
	 * 获取二维码信息
	 * INFO_REQUEST 二维码数据、长度
	 * INFO_RESPONSE 二维码内容，如果同时支持2种协议的二维码，初始化时请2种协议对应的返回参数都初始化
	 */
	info_request.qrcode = qrcode;
	info_request.qrcode_len = qrcode_hex_len/2;

	info_response.proto_type = proto_type;
	//mot
	info_response.code_info->mot_code_info.cert_sn = cert_sn;
	info_response.code_info->mot_code_info.cert_sn_len = sizeof(cert_sn);
	info_response.code_info->mot_code_info.card_issuer_no = card_issuer_no;
	info_response.code_info->mot_code_info.card_issuer_no_len = sizeof(card_issuer_no);
	info_response.code_info->mot_code_info.code_issuer_no = mot_code_issuer_no;
	info_response.code_info->mot_code_info.code_issuer_no_len = sizeof(mot_code_issuer_no);
	info_response.code_info->mot_code_info.user_id = mot_user_id;
	info_response.code_info->mot_code_info.user_id_len = sizeof(mot_user_id);
	info_response.code_info->mot_code_info.card_no = mot_card_no;
	info_response.code_info->mot_code_info.card_no_len = sizeof(mot_card_no);
	info_response.code_info->mot_code_info.card_data = mot_card_data;
	info_response.code_info->mot_code_info.card_data_len = sizeof(mot_card_data);
	//alipay
	info_response.code_info->alipay_code_info.card_type = card_type;
	info_response.code_info->alipay_code_info.card_type_len = sizeof(card_type);
	info_response.code_info->alipay_code_info.code_issuer_no = alipay_code_issuer_no;
	info_response.code_info->alipay_code_info.code_issuer_no_len = sizeof(alipay_code_issuer_no);
	info_response.code_info->alipay_code_info.user_id = alipay_user_id;
	info_response.code_info->alipay_code_info.user_id_len = sizeof(alipay_user_id);
	info_response.code_info->alipay_code_info.card_no = alipay_card_no;
	info_response.code_info->alipay_code_info.card_no_len = sizeof(alipay_card_no);
	info_response.code_info->alipay_code_info.card_data = alipay_card_data;
	info_response.code_info->alipay_code_info.card_data_len = sizeof(alipay_card_data);

	ret = get_qrcode_info(&info_request, &info_response);
	print_info_response(&info_response);
	if(ret != SUCCESS){
		printf("ret = %d\n", ret);
		switch(ret){
			case MALFORMED_QRCODE:
				printf("二维码格式错误！请提示用户二维码错误。\n");
			break;
			case NO_ENOUGH_MEMORY:
				printf("内存不足，极端错误，请检查程序运行空间是否足够。\n");
			break;
			case ILLEGAL_PARAM:
				printf("参数错误！请确认入参是否正确。\n");
			break;
			case SYSTEM_ERROR:
				printf("系统异常！请联系支付宝技术人员。\n");
			break;
			default:
			break;
		}
		printf("获取二维码信息结束！获取失败！\n");
		printf("===========例程结束================\n");
		uninit();
		return;
	}
	printf("get qrcode info ret = %d\n", ret);
	
	/**
	 * 获取二维码信息后，请根据二维码信息获取指定的密钥，在验证时传入
	 */

	/**
	 * pos_param中填入商户pos相关信息 至少包括：
	 *		- record_id	  (记录id，商户下本次脱机记录唯一id号，record_id必须保证商户唯一，建议通过POS，时间等信息拼装)
     *      - pos_id      (商户下唯一的pos号)
     *      - pos_mf_id   (终端制造商id)
     *      - pos_sw_version (终端软件版本)
     *      - merchant_type （商户mcc码）
     *      - currency (币种 人民币请填入156)
     *      - amount （交易金额， 单位：分）
     *      - vehicle_id （车辆id）
     *      - plate_no  (车牌号)
     *      - driver_id （司机号）
     *      - line_info (线路信息)
     *      - station_no (站点信息)
     *      - lbs_info (地理位置信息)
     *      - record_type (脱机记录类型，公交场景为"BUS", 地铁场景为"SUBWAY")
     */
	POS_PARAM_STRUCT pos_param_struct;
	// = (POS_PARAM_STRUCT *)malloc(sizeof(POS_PARAM_STRUCT));
	pos_param_struct.record_id = "sh001_20160514140218_000001";
	pos_param_struct.consumption_type = 0;
	pos_param_struct.pos_id = "20170000000001";
	pos_param_struct.pos_mf_id = "9998112123";
	pos_param_struct.pos_sw_version = "2.6.14.03arm";
	pos_param_struct.merchant_type = "22";
	pos_param_struct.currency = "156";
	pos_param_struct.amount = 2000;
	pos_param_struct.vehicle_id = "vid9702";
	pos_param_struct.plate_no = "粤A 095852";
	pos_param_struct.driver_id = "0236245394";
	pos_param_struct.line_info = "795";
	pos_param_struct.station_no = "asd";
	pos_param_struct.lbs_info = "aaaa";	
	pos_param_struct.record_type = "SUBWAY";


	printf("===========准备数据结束================\n");
	
	printf("===========校验二维码开始================\n");
	//拼装验证请求
	VERIFY_REQUEST_V3 verify_request;
	//装入二进制格式的二维码
	verify_request.qrcode = qrcode;
	//装入二进制二维码长度
	verify_request.qrcode_len = strlen(qrcode_hex)/2;
	//装入pos_param
	verify_request.pos_param_struct = &pos_param_struct;

	//verify_request.public_key = TEST_MOT_DOUBLE_SM2_KEY;
	//verify_request.public_key = TEST_MOT_TRIPLE_SM2_KEY;
	verify_request.public_key = TEST_ALIPAY_PUBLIC_KEY;
	VERIFY_RESPONSE_V3 verify_response;
	verify_response.record = (char*)malloc(2048);
	verify_response.record_len = 2048;

	/**
	 * 调用接口验证二维码的有效性
	 */
	ret = verify_qrcode_v3(&verify_request, &verify_response);

	/**
	 * 处理返回的结果
	 */
	if(ret != SUCCESS){
		printf("ret = %d\n", ret);
		switch(ret){
			case MALFORMED_QRCODE:
				printf("二维码格式错误！请提示用户二维码错误。\n");
			break;
			case QRCODE_INFO_EXPIRED:
				printf("二维码过期！请提示用户刷新二维码。\n");
			break;
			case QRCODE_KEY_EXPIRED:
				printf("二维码密钥过期！请提示用户联网后刷新二维码再使用。\n");
			break;
			case POS_PARAM_ERROR:
				printf("商户传入的pos_param错误，请检查传入的pos_param。\n");
			break;
			case QUOTA_EXCEEDED:
				printf("单笔额度超限！请提示用户由于额度限制无法过闸机。\n");
			break;
			case NO_ENOUGH_MEMORY:
				printf("内存不足，极端错误，请检查程序运行空间是否足够。\n");
			break;
			case ILLEGAL_PARAM:
				printf("参数错误！请确认入参是否正确。\n");
			break;
			case CARDTYPE_UNSUPPORTED:
				printf("此机具不支持二维码对应的卡类型！\n");
			break;
			case QRCODE_DUPLICATED:
				printf("二维码重复！请提示用户刷新二维码。\n");
			break;
			case SYSTEM_ERROR:
				printf("系统异常！请联系支付宝技术人员。\n");
			break;
			default:
			break;
		}
		printf("二维码校验结束！验证失败，不放行！\n");
		printf("===========验证二维码例程 结束================\n");
		free(verify_response.record);
		uninit();
		return;
	}
	printf("验证成功后，返还的脱机记录: %s\n", verify_response.record);

	/**
	 * 1.商户可以根据uid判断是否为同一用户重复交易
	 */
	
	/**
	 * 2.商户可以根据qrcode判断是否为重复二维码
	 *   此判断也可以放在校验二维码前执行，商户可以自行选择
	 */

	/**
	 * 3.商户需要根据卡类型、卡号、卡数据 综合判断该卡的合法性、以及是否受理该卡
	 * 请商户保留 可受理 的脱机记录
	 */
	free(verify_response.record);
	printf("验证成功，请放行！\n");
	printf("===========验证二维码例程 结束================\n");
}

static int demo_init(){
	int ret = 0;
	INIT_REQUEST init_request;
	INIT_INFO *init_info_list[2];

	char* card_types[3] = {0};
	INIT_INFO *init_info_mot = (INIT_INFO *)malloc(sizeof(INIT_INFO));

	init_info_mot->proto_type = "MOT";
	init_info_mot->card_type_number = 0;
	init_info_mot->code_issuer_no = "50023301";

	init_info_list[0] = init_info_mot;

	INIT_INFO *init_info_alipay = (INIT_INFO *)malloc(sizeof(INIT_INFO));

	char* card_type_a = "ANT00001";
	char* card_type_b = "T0420100";
	char* card_type_c = "S0JP0000";
	card_types[0] = card_type_a;
	card_types[1] = card_type_b;
	card_types[2] = card_type_c;
	init_info_alipay->proto_type = "ALIPAY";
	init_info_alipay->card_type_number = 3;
	init_info_alipay->code_issuer_no = "00000000";
	init_info_alipay->card_types = (const char **)card_types;

	init_info_list[1] = init_info_alipay;
	init_request.code_issuer_info_number = 2;
	init_request.code_issuer_infos = init_info_list;
	ret = init(&init_request);
	free(init_info_mot);
	return ret;
}
/**
* 字节数组转hex格式字符串
* @param print_buf: 十六进制字符串buffer
* @param print_buf_len: 十六进制字符串buffer长度
* @param bytes: 二进制数据
* @param bytes_len: 二进制数据长度
*/
char* bytes_to_hex_string(
	char* print_buf, 
	int print_buf_len, 
	const unsigned char* bytes, 
	int len) {

	int i = 0;

	/**
	* 入参校验
	*/ 
	if(print_buf == NULL || bytes == NULL || (len * 2 + 1) > print_buf_len) {
		return NULL;
	}

	for(i = 0; i < len; i++) {
		print_buf[i * 2] = g_hex_map_table[(bytes[i] >> 4) & 0x0F];
		print_buf[i * 2 + 1] = g_hex_map_table[(bytes[i]) & 0x0F];
	}
	/**
	* 填充字符串结束符
	*/
	print_buf[i * 2] = '\0';
	/**
	* 返回目标地址
	*/
	return print_buf;
}
/**
 * 判断这个char是否是hex格式
 * @param c 
 */
static int is_hex_format(char c){
	int ret = -1;
	if(c >= '0' && c <= '9') {
		ret = 1;
	}
	else if(c >= 'A' && c <= 'F') {
		ret = 1;
	}
	else if(c >= 'a' && c <= 'f') {
		ret = 1;
	}
	return ret;
}
/**
* hex格式字符串转字节数组
* @param hex_string: 十六进制字符串
* @param hex_string_len: 十六进制字符串长度
* @param bytes: 二进制数据存储空间
* @param bytes_len: 目标空间长度
*/
int hex_string_to_bytes(
	char* hex_string, 
	int hex_string_len, 
	unsigned char* bytes, 
	int bytes_len) {
	
	int i = 0;
	/**
	* 校验十六进制字符串长度必须偶数，并且目标存储空间必须足够存放转换后的二进制数据
	*/
	if((hex_string_len % 2 != 0) || (bytes_len * 2 < hex_string_len)) {

		printf("bytes_len = %d hex_string_len = %d\n", bytes_len, hex_string_len);
		return -1;
	}
	
	for(i = 0; i < hex_string_len; i += 2) {
		if(is_hex_format(hex_string[i]) != 1){
			return -1;
		}
		bytes[i/2] = ((hex_of_char(hex_string[i]) << 4) & 0xF0) | 
					(hex_of_char(hex_string[i + 1]) & 0x0F);
	}
	return 1;
	return 1;
}

static void print_info_response(INFO_RESPONSE *response){
	printf("response->proto_type = %s\n", response->proto_type);
	if(strcmp(response->proto_type, MOT_PROTO_TYPE) == 0){
		printf("二维码格式为交通部协议\n");

		printf("code_issuer_no = %s\n", response->code_info->mot_code_info.code_issuer_no);
		printf("card_issuer_no = %s\n", response->code_info->mot_code_info.card_issuer_no);
		printf("user_id = %s\n", response->code_info->mot_code_info.user_id);
		printf("card_no = %s\n", response->code_info->mot_code_info.card_no);

	}else if(strcmp(response->proto_type, ALIPAY_PROTO_TYPE) == 0){
		printf("二维码格式为支付宝协议\n");

		printf("key id = %d\n", response->code_info->alipay_code_info.key_id);
		printf("alg id = %d\n", response->code_info->alipay_code_info.alg_id);
		printf("card type = %s\n", response->code_info->alipay_code_info.card_type);
		printf("user_id = %s\n", response->code_info->alipay_code_info.user_id);
		printf("card_no = %s\n", response->code_info->alipay_code_info.card_no);

	}
}
/**
* hex格式char转二进制
*/
unsigned char hex_of_char(char c) {
	unsigned char tmp = 0;
	if(c >= '0' && c <= '9') {
		tmp = (c - '0');
	}
	else if(c >= 'A' && c <= 'F') {
		tmp = (c - 'A' + 10);
	}
	else if(c >= 'a' && c <= 'f') {
		tmp = (c - 'a' + 10);
	}
	return tmp;
}


int main(int argc, char** argv) {
	check_qrcode_demo();
	return 0;
}
