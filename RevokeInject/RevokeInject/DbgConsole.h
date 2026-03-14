#pragma once
#include <stdio.h>
#include <windows.h>

class DbgConsole
{
public:
    static DbgConsole* getInstance()
    {
        if (!_instance)
        {
            _instance = new DbgConsole();
        }
        return _instance;
    }

    static void freeInstance()
    {
        if (_instance)
        {
            delete _instance;
            _instance = NULL;
        }

    }
private:
    DbgConsole()
    {
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
            AllocConsole();
            //SetConsoleCP(65001); SetConsoleOutputCP(65001);
            SetConsoleTitle(TEXT("RevokeInject调试信息控制台"));
        }

        FILE* fp;
        freopen_s(&fp, "conin$", "r+t", stdin);
        freopen_s(&fp, "conout$", "w+t", stdout);
        freopen_s(&fp, "conout$", "w+t", stderr);

        //puts("[ 调试控制台已开启 ]\n");
    }

    ~DbgConsole()
    {
        fclose(stderr);
        fclose(stdout);
        fclose(stdin);
        FreeConsole();
    }

    static DbgConsole* _instance;
};

DbgConsole* DbgConsole::_instance;
