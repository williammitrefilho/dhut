#include <stdio.h>
//#include <windows.h>
#include <gerio.h>
#include <basics.h>
#include <string.h>

struct dados_login{
    
    HANDLE usuario;
    HANDLE senha;
};

unsigned short getDadosLogin(LPSTR cmdLine, struct dados_login *dados){
	
	LPSTR pSenha = cmdLine;
	while(pSenha[0] != 0x00 && pSenha[0] != 0x20)
		pSenha++;
	
	if(pSenha[0] == 0x20){
		
		pSenha[0] = 0x00;
		pSenha++;
	}
	
	dados->usuario = cmdLine;
	dados->senha = pSenha;
	
	return 0;
}

DWORD WINAPI ThreadProc1(LPVOID lpParam){
    
    HWND janela = (HWND)lpParam;
    
    struct gerio_client *client = (struct gerio_client*)GetProp(janela, "client");
    struct dados_login *dados = (struct dados_login*)GetProp(janela, "dados_login");
    
    unsigned short ret = gerio_login(client, "gerio.app", "443", dados->usuario, dados->senha);
    if(!ret){
    
        if(client->logged_in){
            
            printf("id_sessao:%s\n", client->session_id);
            SendMessage(janela, WM_APP+1, 0, 0);
        }
    }
    return 0;
}

DWORD WINAPI ThreadProc2(LPVOID lpParam){
    
    HWND janela = (HWND)lpParam;
    
    struct gerio_client *client = (struct gerio_client*)GetProp(janela, "client");
    
    if(client->logged_in){

        struct gerio_transacao transacao = {0, 0, 0};
        unsigned short ret = gerio_get_transacao(client, &transacao);
        if(!ret){
            
            printf("transacao:%d %d\n", transacao.tid, transacao.valor);
//            gerio_transacao_para_tef(&transacao);
/*            
            HANDLE hTimer = CreateWaitableTimer(0, TRUE, 0);
            SetProp(janela, "timer", hTimer);
            LARGE_INTEGER itime;
            itime.QuadPart = -10000000;
            unsigned short nt = 120, ct = 0;
            if(hTimer){
                
                while(ct < nt){
                    
                    if(!SetWaitableTimer(hTimer, &itime, 0, 0, 0, 0)){
                        
                        printf("erro:%d\n", GetLastError());   
                    }
                    printf("esperando...\n");
                    WaitForSingleObject(hTimer, 1000);
                    printf("voltamos. Tem algo no arquivo?\n");
                    if(!gerio_tef_para_transacao(&transacao)){
                        
                        break;
                    }
                    ct++;
                }
            }
            
            if(!transacao.status){
            
                gerio_cancelar_tef(&transacao); 
                transacao.status = 9;   
            }
            gerio_set_transacao(client, &transacao);
			gerio_confirmar_tef(&transacao);*/
        }
        else if(ret == 2){
        
            printf("conexao falhou. resetando cliente gerio...\n");
            free_gerio_client(client);
            client = new_gerio_client();
            SetProp(janela, "client", client);
            struct dados_login *dados = (struct dados_login*)GetProp(janela, "dados_login");
    
            unsigned short ret = gerio_login(client, "gerio.app", "443", dados->usuario, dados->senha);
            if(!ret){
            
                if(client->logged_in){
                    
                    printf("id_sessao:%s\n", client->session_id);
                }
            }
        }
        PostMessage(janela, WM_APP+2, 0, 0);
    }
    return 0;
}

LRESULT WINAPI WndProc1(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam){
    
//    printf("recebemos:%d\n", uMsg);
    if(uMsg == WM_CREATE){
        
        WSADATA wsData;
        WSAStartup(MAKEWORD(2, 2), &wsData);
        
        struct gerio_client *client = new_gerio_client();
        SetProp(hwnd, "client", (HANDLE)client);
        
        HWND botaoLogin = CreateWindow("BUTTON", "Login?", WS_CHILD, 30, 30, 150, 30, hwnd, 0, 0, 0);
        ShowWindow(botaoLogin, SW_SHOW);
    }
    else{
        
        struct gerio_client *client = (struct gerio_client*)GetProp(hwnd, "client");
        if(uMsg == WM_DESTROY){
            /*
            struct dados_login *dados = (struct dados_login*)GetProp(hwnd, "dados_login");
            if(dados){
                
                HANDLE hHeap = GetProcessHeap();
                HeapFree(hHeap, 0, dados->usuario);
                HeapFree(hHeap, 0, dados->senha);
                
				HeapFree(hHeap, 0, dados);
            }
			*/
            HANDLE hThread = GetProp(hwnd, "Thread"), hThread2 = GetProp(hwnd, "Thread2"), hTimer = GetProp(hwnd, "timer");
            WaitForSingleObject(hThread, 5000);
            if(hTimer){
                
                WaitForSingleObject(hTimer, 1000);
                CloseHandle(hTimer);
            }
            WaitForSingleObject(hThread2, 100000);
            CloseHandle(hThread2);
            CloseHandle(hThread);
            free_gerio_client(client);
            WSACleanup();
            PostQuitMessage(0);
            return 0;
        }
        else if(uMsg == WM_COMMAND){
            
            HWND hBotao = GetWindow(hwnd, GW_CHILD);
            HWND wLogin = CreateWindow("Formulario", "Login", 0, 30, 30, 400, 200, hwnd, 0, 0, 0);
            ShowWindow(hBotao, SW_HIDE);
            ShowWindow(wLogin, SW_SHOW);
        }
        else if(uMsg == WM_APP){
            
            struct dados_login *dados = (struct dados_login*)lParam;
            SetProp(hwnd, "dados_login", dados);
            printf("usuario:%s\nsenha:%s\n", dados->usuario, dados->senha); 
            
            HWND botao = GetWindow(hwnd, GW_CHILD);
            SendMessage(botao, WM_SETTEXT, 0, (LPARAM)"Logando...");
            ShowWindow(botao, SW_SHOW);
            HANDLE hThread = CreateThread(0, 0, ThreadProc1, hwnd, 0, 0);
            SetProp(hwnd, "Thread", hThread);
        }
        else if(uMsg == WM_APP+1){
            
            MessageBox(hwnd, "Logado! recebendo mensagens", "Logado", MB_OK);
            HANDLE hThread2 = CreateThread(0, 0, ThreadProc2, hwnd, 0, 0);
            SetProp(hwnd, "Thread2", hThread2);
        }
        else if(uMsg == WM_APP+2){
            
            printf("um ciclo\n");
            HANDLE hThread2 = GetProp(hwnd, "Thread2");
            WaitForSingleObject(hThread2, 1000);
            CloseHandle(hThread2);
            hThread2 = CreateThread(0, 0, ThreadProc2, hwnd, 0, 0);
            SetProp(hwnd, "Thread2", hThread2);
        }   
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT WINAPI WndProc2(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam){
    
//    printf("recebemos:%d\n", uMsg);
    if(uMsg == WM_CREATE){
        
        CREATESTRUCT *cs = (CREATESTRUCT*)lParam;
        HWND textoLogin = CreateWindow("EDIT", "Login?", WS_CHILD, 30, 30, 150, 30, hwnd, 0, 0, 0);
        HWND textoSenha = CreateWindow("EDIT", "Senha?", WS_CHILD | ES_PASSWORD, 30, 70, 150, 30, hwnd, 0, 0, 0);
        HWND botaoLogin = CreateWindow("BUTTON", "acessar", WS_CHILD, 30, 110, 150, 30, hwnd, 0, 0, 0);
        ShowWindow(textoLogin, SW_SHOW);
        ShowWindow(textoSenha, SW_SHOW);
        ShowWindow(botaoLogin, SW_SHOW);
        
        SetProp(hwnd, "textoLogin", textoLogin);
        SetProp(hwnd, "textoSenha", textoSenha);
        SetProp(hwnd, "botaoLogin", botaoLogin);
    }
    else{
    
        if(uMsg == WM_DESTROY){

            
        }
        else if(uMsg == WM_COMMAND){
            
            
            HWND botaoLogin = GetProp(hwnd, "botaoLogin");
            if((HWND)lParam == botaoLogin){
            
                HWND textoLogin = GetProp(hwnd, "textoLogin"),
                        textoSenha = GetProp(hwnd, "textoSenha");
                LRESULT tamanhoLogin = SendMessage(textoLogin, WM_GETTEXTLENGTH, 0, 0),
                            tamanhoSenha = SendMessage(textoSenha, WM_GETTEXTLENGTH, 0, 0);
                
                HANDLE tLogin = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tamanhoLogin+1);
                HANDLE tSenha = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tamanhoSenha+1);
                HANDLE tDados = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct dados_login));
                
                SendMessage(textoLogin, WM_GETTEXT, tamanhoLogin+1, (LPARAM)tLogin);
                SendMessage(textoSenha, WM_GETTEXT, tamanhoSenha+1, (LPARAM)tSenha);
                
                struct dados_login *sDados = (struct dados_login*)tDados;
                sDados->usuario = tLogin;
                sDados->senha = tSenha;
                SendMessage(GetWindow(hwnd, GW_OWNER), WM_APP, 0, (LPARAM)tDados);
                ShowWindow(hwnd, SW_HIDE);
                DestroyWindow(hwnd);
            }
        } 
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR nCmdLine, int nShowCmd){
    
    MSG msg;
    WNDCLASS windowClass = {       
        0,
        WndProc1,
        0,
        0,
        hInstance,
        0,
        0,
        (HBRUSH)COLOR_BACKGROUND,
        0,
        "MainClass"    
    }, classForm = {       
        0,
        WndProc2,
        0,
        0,
        hInstance,
        0,
        0,
        (HBRUSH)COLOR_BACKGROUND,
        0,
        "Formulario"    
    };
    ATOM hClass = RegisterClass(&windowClass);
    if(!hClass){
        
        printf("erro regclass:%d\n", GetLastError());
        return 1;
    }
    hClass = RegisterClass(&classForm);
    if(!hClass){
        
        UnregisterClass("MainClass", hInstance);
        printf("erro regclassform:%d\n", GetLastError());
        return 1;
    }
    HWND hwnd = CreateWindow("MainClass", "Janela 1", WS_OVERLAPPEDWINDOW, 0, 0, 500, 300, 0, 0, hInstance, 0);
    if(!hwnd){
        
        UnregisterClass("MainClass", hInstance);
        UnregisterClass("Formulario", hInstance);
        
        printf("erroCreate:%d\n", GetLastError());
        return 1;
    }
    struct dados_login d_login;
	if(nCmdLine[0] != 0x00){
		
		getDadosLogin(nCmdLine, &d_login);
		unsigned char *pSenha = (unsigned char*)d_login.senha;
		if(pSenha[0] != 0x00)
			SendMessage(hwnd, WM_APP, 0, (LPARAM)&d_login);
	}
    ShowWindow(hwnd, 1);
    UpdateWindow(hwnd);
    while(GetMessage(&msg, 0, 0, 0)){
    
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}