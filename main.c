/*  main.c
 *  tracing procedure algorithm
 *  1 May 2001: extend with example
 * 
 */

#include <stdio.h>
#include <string.h>	/* strcpy		*/
#include <stdlib.h>	/* atoi(), free()       */
#include <ctype.h>	/* isprint()            */
/* #include <unistd.h> */
	/* getopt(), optarg, optopt, optind             */
#include <time.h>
	/* clock_t, clock(), CLOCKS_PER_SEC     	*/
#include <limits.h>
        /* INT_MAX,  INT_MIN    */

#include "alloc.h"
#include "rat.h"
#include "lemke.h"
#include "mp.h"         /* record_digits, DIG2DEC()     */
#include "treedef.h"
#include "treegen.h"
#include "sfnf.h"
#include "seqform.h"
#include "prior.h"

#define MINLEVEL 1      
#define MAXLEVEL 10
#define FILENAMELENGTH 50
#define CLOCKUNITSPERSECOND 1000.0
#define SCLOCKUNITS "millisecs"
#define REPEATHEADER 20   /* repeat header if more games than this */

/* global variables for generating and documenting computation  */
static  Flagsprior    fprior;
static  Bool boutlcp = 0;       /* output LCP       (-o option) */
static  Bool boutprior = 0;     /* output prior     (-O option) */
static  Bool bcomment = 0;      /* complementary pivoting steps */
static  Bool bequil = 1;        /* output equilibrium           */
static  Bool bshortequil = 0;   /* output equilibrium shortly   */
static  Bool binterface = 0;  	/* interface with enumeration	*/
/* GAMBIT interface file, option parameter	*/
static  char gintfname[FILENAMELENGTH] = "dummyname" ;
static  Flagsrunlemke flemke;

static  int timeused , sumtimeused ;
static  int pivots   , sumpivots   ;
static  int lcpsize  ;
static  int mpdigits , summpdigits ;
static  int eqsize [PLAYERS] , sumeqsize [PLAYERS] ;
static  Bool agreenfsf [PLAYERS] ;


/* returns processor SCLOCKUNITS since the last call to
 * stopwatch() and prints them to stdout if  bprint==1
 */
int stopwatch(Bool bprint)
{
    static clock_t time;
    double x;

    x = (double) (clock()) - (double) time;
    if (x < 0)
    	x += 2 * (double) INT_MAX;
    x /= ((double) CLOCKS_PER_SEC / CLOCKUNITSPERSECOND) ;
    if (bprint)
	printf("time elapsed [%s] %4.0f\n", SCLOCKUNITS, x);
    time = clock();
    return (int) x;
}

/* informs about tree size              */
void infotree()
{
    int pl;
    printf("\nGame tree has %d nodes, ", lastnode - root);
    printf("of which %d are terminal nodes.\n", lastoutcome - outcomes);
    for (pl = 0; pl < PLAYERS; pl++)
	{
	printf("    Player %d has ", pl);
	printf("%3d information sets, ", firstiset[pl+1] - firstiset[pl]);
	printf("%3d moves in total\n", firstmove[pl+1] - firstmove[pl] - 1); 
	}
}

/* informs about sequence form, set  lcpsize    */
void infosf()
{
    int pl;
    
    lcpsize = nseqs[1] + nisets[2]+1 + nseqs[2] + nisets[1]+1 ;
    printf("Sequence form LCP dimension is %d\n", lcpsize );
    for (pl = 1; pl < PLAYERS; pl++)
	{
	printf("    Player %d has ", pl);
	printf("%3d sequences, ", nseqs[pl]);
	printf("subject to %3d constraints\n", nisets[pl]+1); 
	}
} 

/* give header columns for result information via  inforesult(...)      */
void inforesultheader ()
{
    printf("PRIOR/PAY| ");
    printf("SEQUENCE FORM        mixiset");
    printf("\n");
    printf("Seed/seed| ");
    printf("pivot %%n [secs] digs pl1 pl2");
	printf("\n");
}

/* info about results for game with  priorseed  and  (payoff) seed */
void inforesult (int priorseed, int seed)
{
    char formatstring[] = "%4d %3.0f %6.2f  %3d %3d %3d" ;
    printf("%4d/%4d| ", priorseed, seed);
	printf(formatstring, pivots, 
            (double) pivots*100.0 / (double) lcpsize ,
	    (double) timeused  / CLOCKUNITSPERSECOND,
	    mpdigits , eqsize [1] , eqsize [2] );
    printf("\n");
}

/* summary info about results for  m  games     */
void infosumresult ( int m)
{
    double mm = (double) m;
    char formatstring[] = "%6.1f %3.0f %6.2f %4.1f %3.1f %3.1f" ;
    
    printf("---------| AVERAGES over  %d  games:\n", m);
    if (m > REPEATHEADER)
        inforesultheader ();
    printf("         ");
	printf(formatstring, (double) sumpivots / mm, 
            (double) sumpivots *100.0 /
                (double) (lcpsize  * mm),
	    (double) sumtimeused  / (CLOCKUNITSPERSECOND * mm),
	    (double) summpdigits  / mm, 
            (double) sumeqsize [1]  / mm, 
            (double) sumeqsize [2]  / mm);
    printf("\n");
}

/* process game for evaluation
 * for comparison:  call first for  NF  then  SF
 * bnf:  NF is processed, compare result with SF result
 * docuseed:  what seed to output for short equilibrium output
 * realplan[][]  must be allocated
 */
void processgame (int docuseed)
{
    int equilsize;
    int offset;
    int pl;

	if (bcomment)
		printf("Generating and solving sequence form.\n");
	sflcp();

    covvector();
    if (boutlcp)
	outlcp();
    stopwatch(0);
    record_digits = 0;
    runlemke(flemke);
    sumtimeused += timeused =
	stopwatch(0);
    sumpivots  += pivots  =
	pivotcount;
    summpdigits  += mpdigits  =
	Dig2Dec(record_digits);
    /* equilibrium size     */
    offset = 0;
    for (pl = 1; pl < PLAYERS; pl++)
	{
		equilsize = propermixisets(pl, solz + offset);
		/* the next is  offset  for player 2 */
		offset = nseqs[1] + 1 + nisets[2];
	
	sumeqsize [pl]  +=
	    eqsize [pl]  = equilsize ;
	}
    if (bequil)
	showeq (bshortequil, docuseed); 
}


int main(int argc, char *argv[])
{
    int levels = 0;     /* which game to process,   (-l option)
			 * 0:  tracing example BvS/Elzen/Talman,
			 * -1: forward induction example
			 * MINLEVEL..MAXLEVEL:  bintree
			 */
  
    int multipriors = 0;         /* parameter for    -M option  */
    int seed  = 0;      /* payoff seed for bintree  (-s option) */

    Bool bheadfirst = 0;/* headers first (multiple games)       */
    Bool bgame = 0;     /* output the raw game tree (-g option) */

    flemke.maxcount   = 0;
    flemke.bdocupivot = 1; 
    flemke.binitabl   = 0;
    flemke.bouttabl   = 1;
    flemke.boutsol    = 1;
    flemke.blexstats  = 1;

    fprior.seed       = 0 ;
    fprior.accuracy   = DEFAULTACCURACY ;

    /* parse options    */
    /* options have been input, amend extras	*/
    if (multipriors > 0)
	{
	/* this would exclude the centroid for multiple priors
        if ( fprior.seed == 0)
            fprior.seed = 1 ; 
	*/
        }
    else
        multipriors = 1 ;
    if (bcomment)
	    {
            flemke.bdocupivot = 1;
            flemke.boutsol    = 1;
	    }

    /* options are parsed and flags set */
    /* document the set options         */
    printf("Options chosen,              [ ] = default:\n");
    printf("    Multiple priors     %4d [1],  option -M #\n", multipriors);
    printf("    Accuracy prior      %4d [%d], option -A #\n",
	    fprior.accuracy, DEFAULTACCURACY);
    printf("    Seed prior           %3d [0],  ",
            fprior.seed);
    printf("    Output prior           %s [N],  option -O\n",
            boutprior ? "Y" : "N");
    printf("    game output            %s [N],  option -g\n",
	    bgame ? "Y" : "N");
    printf("    comment LCP pivs & sol %s [N],  option -c\n",
            bcomment ? "Y" : "N");
    printf("    output LCP             %s [N],  option -o\n",
            boutlcp ? "Y" : "N");
    printf("    degeneracy statistics  %s [N],  option -d\n",
	    flemke.blexstats ? "Y" : "N");
    printf("    tableaus               %s [N],  option -t\n",
	    flemke.bouttabl ? "Y" : "N");
                    

	printf("Solving example from BvS/Elzen/Talman\n");
	tracingexample();

    genseqin();  
    autoname();
    maxpayminusone(bcomment);

    /* game tree is defined, give headline information  */
    infotree(); // INFO
        
	    infosf(); // INFO
    
        /* process games                    */
	    int gamecount = 0;
	    int startprior = fprior.seed ;
    
	    allocrealplan(realplan);
            if (bheadfirst) /* otherwise the header is garbled by LCP output */
                inforesultheader ();
	    int priorcount ;
            /* multiple priors 	*/
		bgame = 1; 
		boutprior = 1; 
		multipriors = 1; 
	    for (priorcount = 0; priorcount < multipriors; priorcount++)
	        {
	        genprior(fprior);
                if (bgame)
        	    rawtreeprint();
                if (boutprior)
        	    outprior();
	        processgame(seed + gamecount); 
                if ( ! bheadfirst )
                    inforesultheader ();
	        inforesult (fprior.seed, seed + gamecount);
                fprior.seed++ ;
	        }
	    if (multipriors > 1)	/* give averages */
	        infosumresult (multipriors);
	    freerealplan(realplan);
    return 0;
}
