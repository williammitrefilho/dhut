#include <windows.h>
#include <sqlext.h>
#include <stdio.h>
#include <string.h>

unsigned char gerio_gcom_fmt_venda_direta[] = "INSERT INTO venda_direta (nr_orc_loc, ic_tip_ope, dt_vnd_dir, id_tip_nf, id_uti_pro, nm_pes_cli, id_etb_cli, id_usu_req, id_end_geo_fat, id_end_geo_etg, id_end_geo_cob, id_pes_atd, vl_tot_ite, vl_bon, vl_tot_dsc, vl_tot_vnd, pc_dsc, id_cnd_pag, ic_tp_ent, dt_ent, vl_ent, dt_pri_prst, qp_pri_prst, id_vnd_dir, vl_tot_prl, vl_tot_frt, dt_vnd_ini, hr_vnd_ini, hr_vnd_dir, vl_tx_srv, dc_obs_ger, nr_cpf_cnpj_cli, nr_pre_vnd, nr_dav, cd_hash, cd_ver_gcom, vl_tot_icms_des, id_fas_ped, id_tip_atd, vl_troco, ic_tip_ret, vl_doa, id_mrc, ic_makeline, ic_obr_producao, cd_ser_eqp_papa_fila, nr_tel_cli, id_turno, nm_comp_fez_vnd, vl_tot_seg, vl_tot_dsp_acs, vl_cashback_resg) VALUES (%s)";

unsigned char gerio_gcom_fmt_venda_direta_campos[] = "%d, 'V', '%s', '68411', '1', 'CONSUMIDOR FINAL', '10876743', '0', '10910455', '10910455', '10910455', '58943', '%f', '0.0', '%f', '%f', '%f', '0', '0', '%s', '0.0', '%s', '0', '%d', '%f', '0.0', '%s', '%s', '%s', '0.0', '', '%s', '0.0', '0.0', 'HADNEV', '4.7.14', '0.0', 'L', 'BC', '%f', 'BALCAO', '0.0', '88', 'N', 'N', '', '', '0', 'DESKTOP-5IJNJS5', '0.0', '0.0', '0.0'";

struct gerio_diag_state{
    
    unsigned short diag_num;
} gerio_diag_st;

typedef struct gerio_gcom_venda_direta{
	
	unsigned long nr_orc_loc;
	unsigned long id_venda;
	
	unsigned long data;
	unsigned long hora;
	unsigned char cpfcnpj[15];
	
	float valor_itens;
	float valor_desconto;
	float valor_venda;
	float perc_desconto;
	float valor_troco;
} gerio_gcom_venda_direta;

unsigned long gerio_gcom_data_hora(unsigned short a, unsigned char b, unsigned char c){
	
	return (a << 16) | (b << 8) | c;
}

typedef struct gerio_sql_diag{
	
	unsigned char tState[6];
	unsigned char tText[512];
	unsigned long rCode;
} gerio_sql_diag;

int gerio_diag(SQLINTEGER handleType, SQLHANDLE handle, gerio_sql_diag *diag){
	
	SQLSMALLINT mLen;
	return SQLGetDiagRec(handleType, handle, 1, diag->tState, &diag->rCode, diag->tText, 128, &mLen);
}

SQLHSTMT gerio_query(SQLHDBC hdbc, unsigned char *query){
	
	SQLINTEGER qLen = 0;
	while(query[qLen]){
		
		qLen++;
	}
	SQLHSTMT hStmt;
	int r = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hStmt);
	if(r < 0){
		
        gerio_sql_diag diag;
		gerio_diag(SQL_HANDLE_DBC, hdbc, &diag);
		printf("ERRO Alloc STMT:ret:%d %s %s\n", r, diag.tState, diag.tText);
		return 0;
	}
	r = SQLExecDirect(hStmt, query, qLen);
	if(r < 0){
		
        gerio_sql_diag diag;
		gerio_diag(SQL_HANDLE_STMT, hStmt, &diag);
		SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
		printf("ERRO STMT:ret:%d %s %s\n", r, diag.tState, diag.tText);
		return 0;
	}
	return hStmt;
}

SQLRETURN gerio_gcom_insert_venda_direta(SQLHDBC hdbc, gerio_gcom_venda_direta *venda){
	
	unsigned char sData[11], sHora[9], sCampos[512], sQuery[2056];

	sprintf(sData, "%04d%02d%02d", venda->data >> 16, (venda->data >> 8) & 0xFF, venda->data & 0xFF);
	sprintf(sHora, "%02d:%02d:%02d", venda->hora >> 16, (venda->hora >> 8) & 0xFF, venda->hora & 0xFF);
	
	sprintf(sCampos, gerio_gcom_fmt_venda_direta_campos, venda->nr_orc_loc, sData, venda->valor_itens, venda->valor_desconto, venda->valor_venda, venda->perc_desconto, sData, sData, venda->valor_venda, venda->id_venda, sData, sHora, sHora, venda->cpfcnpj, venda->valor_troco);	
	sprintf(sQuery, gerio_gcom_fmt_venda_direta, sCampos);
	
//	printf("%s\n", sQuery);
	SQLHSTMT insertStmt = gerio_query(hdbc, sQuery);
	if(!insertStmt){

		return -1;
	}
	SQLFreeHandle(SQL_HANDLE_STMT, insertStmt);
	return 0;
}

int  main(){
	
    gerio_diag_st.diag_num = 1;
	HENV hEnv, hdbc;
	int r = SQLAllocHandle(SQL_HANDLE_ENV, NULL, &hEnv);
	if(r != SQL_SUCCESS){
		
		printf("ERRO Alloc Env:ret:%d\n", r);
		return 1;
	}
	
	SQLSetEnvAttr(hEnv, SQL_ATTR_ODBC_VERSION, (SQLPOINTER)SQL_OV_ODBC3, 0);
	r = SQLAllocHandle(SQL_HANDLE_DBC, hEnv, &hdbc);
	if(r != SQL_SUCCESS){
		
		gerio_sql_diag diag;
		gerio_diag(SQL_HANDLE_ENV, hEnv, &diag);
		SQLFreeHandle(SQL_HANDLE_ENV, hEnv);
		printf("ERRO Alloc DBC:ret:%d %s %s\n", r, diag.tState, diag.tText);
		return 1;
	}
	
	SQLCHAR bBuffer[512];
	SQLSMALLINT bLen;
	r = SQLDriverConnect(hdbc, NULL, "Driver=ODBC Driver 17 for SQL Server;Server=W-MITRE\\SQLEXPRESS;Trusted_Connection=yes", 86, bBuffer, 512, &bLen, SQL_DRIVER_NOPROMPT);
	if(r != SQL_SUCCESS){
		
		gerio_sql_diag diag;
		gerio_diag(SQL_HANDLE_DBC, hdbc, &diag);
		SQLFreeHandle(SQL_HANDLE_ENV, hEnv);
		printf("Info Connect:ret:%d %s %s\n", r, diag.tState, diag.tText);
		if(r != SQL_SUCCESS_WITH_INFO){
			
			SQLFreeHandle(SQL_HANDLE_ENV, hEnv);
			SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
			return 1;
		}
	}
	
	printf("%d %s (%d)\n", r, bBuffer, bLen);
	
	SQLHSTMT hBkp = gerio_query(hdbc, "BACKUP DATABASE GCOM TO DISK = 'C:/GCOM2/GCOM.BKG' WITH DIFFERENTIAL");
	
	if(!hBkp){

		printf("erro bkp\n");
	}
    else{
	   
       SQLFreeHandle(SQL_HANDLE_STMT, hBkp);
    }
	SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
	SQLFreeHandle(SQL_HANDLE_ENV, hEnv);	
	return 0;
	
}