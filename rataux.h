/* rataux.h
 * 12 July 2000
 * auxiliary routines for rational arithmetic
 */

/* #include before: "rat.h" */

/* return the rational number  a/b  that approximates  x  best
 * among all such rationals with  1 <= b <= accuracy
 */ 
Rat contfract(double x, int accuracy);
