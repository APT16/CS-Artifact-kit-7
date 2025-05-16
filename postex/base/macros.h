#pragma once
#define RETURN_ON_NULL(x) if(x == NULL) return;
#define RETURN_NULL_ON_NULL(x) if(x == NULL) return NULL;
#define RETURN_ZERO_ON_NULL(x) if(x == NULL) return 0;
#define RETURN_FALSE_ON_NULL(x) if(x == NULL) return false;
#define RETURN_FALSE_ON_FALSE(x) if(x == FALSE) return FALSE;