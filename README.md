# AmsiPatcher

A C++ implementation of the Remote Amsi patcher that creates a powershell process and patches the functions of your choice, AmsiOpenSession and AmsiScanBuffer

ScanBufferPatch
```cpp
#include <cstdio>
#include "Patcher.h"

int main()
{
	Patcher* patch = new Patcher();
	patch->ScanBufferPatch();
}

```

OpenSessionPatch
```cpp
#include <cstdio>
#include "Patcher.h"

int main()
{
	Patcher* patch = new Patcher();
	patch->OpenSessionPatch();
}

```

If you have any questions, feel free to contact me
