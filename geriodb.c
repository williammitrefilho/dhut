#include <windows.h>
#include <sqlext.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

unsigned char gerio_gcom_fmt_venda_direta[] = "INSERT INTO venda_direta (nr_orc_loc, ic_tip_ope, dt_vnd_dir, id_tip_nf, id_uti_pro, nm_pes_cli, id_etb_cli, id_usu_req, id_end_geo_fat, id_end_geo_etg, id_end_geo_cob, id_pes_atd, vl_tot_ite, vl_bon, vl_tot_dsc, vl_tot_vnd, pc_dsc, id_cnd_pag, ic_tp_ent, dt_ent, vl_ent, dt_pri_prst, qp_pri_prst, id_vnd_dir, vl_tot_prl, vl_tot_frt, dt_vnd_ini, hr_vnd_ini, hr_vnd_dir, vl_tx_srv, dc_obs_ger, nr_cpf_cnpj_cli, nr_pre_vnd, nr_dav, cd_hash, cd_ver_gcom, vl_tot_icms_des, id_fas_ped, id_tip_atd, vl_troco, ic_tip_ret, vl_doa, id_mrc, ic_makeline, ic_obr_producao, cd_ser_eqp_papa_fila, nr_tel_cli, id_turno, nm_comp_fez_vnd, vl_tot_seg, vl_tot_dsp_acs, vl_cashback_resg) VALUES (%s)";
unsigned char gerio_gcom_fmt_venda_direta_campos[] = "%d, 'V', '%s', '68411', '1', 'CONSUMIDOR FINAL', '10876743', '0', '10910455', '10910455', '10910455', '58943', '%f', '0.0', '%f', '%f', '%f', '0', '0', '%s', '0.0', '%s', '0', '%d', '%f', '0.0', '%s', '%s', '%s', '0.0', '', '%s', '0.0', '0.0', 'HADNEV', '4.7.14', '0.0', 'L', 'BC', '%f', 'BALCAO', '0.0', '88', 'N', 'N', '', '', '0', 'DESKTOP-5IJNJS5', '0.0', '0.0', '0.0'";

unsigned char gerio_gcom_fmt_item_venda_direta[] = "INSERT INTO item_venda_direta (nr_orc_loc, id_seq, id_mat_pro, id_tri, pr_un_it_atd, qt_pro_atd, vl_dsc, vl_icms, vl_ipi, vl_icms_rtd, vl_dsc_icms, vl_bas_icms, aq_icms, aq_ipi, vl_pr_un_ori, id_prt_ite, ic_gera_ord_srv, ic_recebe_vnd_sem_ord_srv, dt_vnd_ite, hr_vnd_ite, pc_icms_des, vl_icms_des, vl_bas_pis, vl_bas_cofins, aq_pis, aq_cofins, vl_pis, vl_cofins, vl_dsc_rsg, cd_esp_sub_tri, vl_bas_ipi, vl_bas_icms_des, vl_bas_iss, aq_iss, vl_iss, vl_dsc_cli, vl_dsc_cbo, vl_dsc_man, id_seq_lin, pnt_ite_rsg, id_prt_seg_ite, id_prt_ite_can, vl_frt_prop, vl_dsp_prop, vl_seg_prop, ic_ite_exist_ecf, vl_dsc_cash_back) VALUES (%s)";
unsigned char gerio_gcom_fmt_item_venda_direta_campos[] = "'%d', '%d', '%d', '%d', '%f', '%f', '%f', '%f', '0.0', '0.0', '0.0', '%f', '12.0', '0.0', '%f', 'S', 'N', 'N', '%s', '%s', '0.0', '0.0', '%f', '%f', '0.0', '0.0', '0.0', '0.0', '0.0', '%d', '0.0', '0.0', '0.0', '0.0', '0.0', '0.0', '0.0', '0.0', '0.0', '0.0', 'N', 'N', '0.0', '0.0', '0.0', 'N', '0.0'";

unsigned char gerio_gcom_fmt_insert_recebimento_direto[] = "INSERT INTO item_recebimento_direto (nr_orc_loc, id_seq_lct, id_fma_pgt, dt_vnc_doc, vl_pgt, id_ban_cc, nr_doc, nm_pes_doc, qtd_pcl, id_cxa, id_rede, vl_ctr_val, vl_doa) VALUES (%s)";

unsigned char gerio_gcom_fmt_insert_recebimento_direto_campos[] = "'%d', '%d', '%d', '%s', '%f', '%d', '000000', '1497', '1.0', '5997', '1', '0.0', '0.0'";

struct gerio_diag_state{
    
    unsigned short diag_num;
} gerio_diag_st; 

typedef struct gerio_gcom_item_venda_direta{
    
    unsigned long id_mat_pro;
    unsigned short id_seq;
    unsigned long id_tri;
    unsigned long cd_esp_sub_tri;
    
    float pr_un_it_atd;
    float qt_pro_atd;
    float vl_dsc;
    float vl_icms;
} gerio_gcom_item_venda_direta;

typedef struct gerio_gcom_item_recebimento_direto{
    
    unsigned long id_fma_pgt;
    float vl_pgt;
    unsigned long id_ban_cc;
} gerio_gcom_item_recebimento_direto;

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
    
    unsigned short n_itens;
    gerio_gcom_item_venda_direta **itens;
    
    unsigned short n_pagtos;
    gerio_gcom_item_recebimento_direto **pagtos;
    
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
	if(r){
		
        gerio_sql_diag diag;
		gerio_diag(SQL_HANDLE_STMT, hStmt, &diag);
		printf("info STMT:ret:%d %s %s\n", r, diag.tState, diag.tText);
        if(r < 0){
            
            SQLFreeHandle(SQL_HANDLE_STMT, hStmt);
  		    return 0;
        }
	}
	return hStmt;
}

SQLRETURN gerio_gcom_insert_venda_direta(SQLHDBC hdbc, gerio_gcom_venda_direta *venda){
	
	unsigned char sData[11], sHora[9], sCampos[1024], sQuery[4096];
    
    if(!venda->nr_orc_loc){
        
        SQLHSTMT hMax = gerio_query(hdbc, "SELECT MAX(nr_orc_loc) FROM venda_direta");
        if(!hMax){
            
            printf("erro select");
            return -1;
        }
        SQLLEN sLen;
        SQLBindCol(hMax, 1, SQL_C_ULONG, &venda->nr_orc_loc, 4, &sLen);
        SQLFetch(hMax);
        SQLFreeHandle(SQL_HANDLE_STMT, hMax);
        if(venda->nr_orc_loc < 2000000)
			venda->nr_orc_loc += 2000000;
		else
			venda->nr_orc_loc++;
    }
	sprintf(sData, "%04d%02d%02d", venda->data >> 16, (venda->data >> 8) & 0xFF, venda->data & 0xFF);
	sprintf(sHora, "%02d:%02d:%02d", venda->hora >> 16, (venda->hora >> 8) & 0xFF, venda->hora & 0xFF);
	
	sprintf(sCampos, gerio_gcom_fmt_venda_direta_campos, venda->nr_orc_loc, sData, venda->valor_itens, venda->valor_desconto, venda->valor_venda, venda->perc_desconto, sData, sData, venda->valor_venda, venda->id_venda, sData, sHora, sHora, venda->cpfcnpj, venda->valor_troco);	
	sprintf(sQuery, gerio_gcom_fmt_venda_direta, sCampos);
    printf("%s\n", sQuery);
    
    SQLHSTMT insertStmt = gerio_query(hdbc, sQuery);
	if(!insertStmt){

		return -1;
	}
	SQLFreeHandle(SQL_HANDLE_STMT, insertStmt);
    
    for(int i = 0; i < venda->n_itens; i++){
        
        sprintf(sCampos, gerio_gcom_fmt_item_venda_direta_campos, venda->nr_orc_loc, i+1, venda->itens[i]->id_mat_pro, venda->itens[i]->id_tri, venda->itens[i]->pr_un_it_atd, venda->itens[i]->qt_pro_atd, venda->itens[i]->vl_dsc, venda->itens[i]->pr_un_it_atd*0.12, venda->itens[i]->pr_un_it_atd, venda->itens[i]->pr_un_it_atd, sData, sHora, venda->itens[i]->pr_un_it_atd, venda->itens[i]->pr_un_it_atd, venda->itens[i]->cd_esp_sub_tri);	
	    sprintf(sQuery, gerio_gcom_fmt_item_venda_direta, sCampos);
        printf("%s\n", sQuery);
        SQLHSTMT insertStmt = gerio_query(hdbc, sQuery);
    	if(!insertStmt){
    
    		return -1;
    	}
    	SQLFreeHandle(SQL_HANDLE_STMT, insertStmt);
    }
    
    for(int i = 0; i < venda->n_pagtos; i++){
        
        sprintf(sCampos, gerio_gcom_fmt_insert_recebimento_direto_campos, venda->nr_orc_loc, i+1, venda->pagtos[i]->id_fma_pgt, sData, venda->pagtos[i]->vl_pgt, venda->pagtos[i]->id_ban_cc);	
	    sprintf(sQuery, gerio_gcom_fmt_insert_recebimento_direto, sCampos);
        printf("%s\n", sQuery);
        SQLHSTMT insertStmt = gerio_query(hdbc, sQuery);
    	if(!insertStmt){
    
    		return -1;
    	}
    	SQLFreeHandle(SQL_HANDLE_STMT, insertStmt);
    }

	return 0;
}

int  main(int argc, char *argv[]){
	
    if(argc < 2){
        
        printf("informe DSN\n");
        return 1;
    }
    unsigned short dsn_len = 0;
    while(argv[1][dsn_len]){
        
        dsn_len++;
    }
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
	r = SQLDriverConnect(hdbc, NULL, argv[1], dsn_len, bBuffer, 512, &bLen, SQL_DRIVER_NOPROMPT);
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
	
	gerio_gcom_venda_direta venda;
    
	time_t timestamp = time(0);
	struct tm * local_time = localtime(&timestamp);
    venda.data = gerio_gcom_data_hora(local_time->tm_year + 1900, local_time->tm_mon+1, local_time->tm_mday);
    venda.hora = gerio_gcom_data_hora(local_time->tm_hour, local_time->tm_min, local_time->tm_sec);
    venda.valor_itens = 5;
    venda.valor_desconto = 0;
    venda.valor_venda = 5;
    venda.perc_desconto = 0;
    venda.valor_troco = 0;
    venda.nr_orc_loc = 0;
    venda.cpfcnpj[0] = 0;
    
    gerio_gcom_item_venda_direta item = {
        
        3659524,
        1,
        22092178,
        2804100,
        
        5.0,
        1.0,
        0.0,
        0.0   
    };
    
    gerio_gcom_item_recebimento_direto pagto = {
        
        1,
        5.0,
        51    
    };
    gerio_gcom_item_venda_direta *pitem = &item;
    gerio_gcom_item_recebimento_direto *ppagto = &pagto;
    
    venda.pagtos = &ppagto;
	venda.itens = &pitem;
    venda.n_itens = 1;
    venda.n_pagtos = 1;
    printf("item:%d\n", venda.itens[0]->id_mat_pro);
	gerio_gcom_insert_venda_direta(hdbc, &venda);

	SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
	SQLFreeHandle(SQL_HANDLE_ENV, hEnv);	
	return 0;	
}