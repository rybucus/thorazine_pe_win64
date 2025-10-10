#include "src/defines.h"

int main( )
{
	import( kernel32.dll, Beep )< BOOL >( 100, 500 );
}