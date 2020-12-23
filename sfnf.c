/* sfnf.c
 * 12 July 2000
 * common routines for SF, RSF, NF
 */

#include <stdio.h>
#include <stdlib.h>
        /* free()       */ 

#include "alloc.h"
#include "rat.h"
#include "rataux.h"        /* ratscalarprod        */

#include "lemke.h"
#include "treedef.h"

#include "seqform.h"

#include "sfnf.h"

Rat *realplan[PLAYERS];

void allocrealplan (Rat * realpl[PLAYERS])
{
    int pl;

    for (pl=0; pl < PLAYERS; pl++)
        realpl[pl] = TALLOC (nseqs[pl], Rat);
}

void freerealplan(Rat * realpl[PLAYERS])
{
    int pl;

    for (pl=0; pl < PLAYERS; pl++)
        free(realpl[pl]);
}

void behavtorealprob (int pl)
{
    Move c;
    Move lastmove = firstmove[pl+1];
    firstmove[pl]->realprob = ratfromi(1);  /* empty seq has probability 1  */
    for (c = firstmove[pl]+1; c < lastmove; c++)
        c->realprob = ratmult(c->behavprob, c->atiset->seqin->realprob);
}

void payratmatcpy(Payvec ** frommatr, int plminusone, Bool bnegate,
        Bool btranspfrommatr, int nfromrows, int nfromcols, 
        Rat ** targetmatr, int targrowoffset, int targcoloffset)
{
    int i,j;
    for (i=0; i < nfromrows; i++)
        for (j=0; j < nfromcols; j++)
            if (btranspfrommatr)
                targetmatr[j + targrowoffset][i + targcoloffset]
                = bnegate ? ratneg(frommatr[i][j][plminusone]) : frommatr[i][j][plminusone] ;
            else 
                targetmatr[i + targrowoffset][j + targcoloffset]
                = bnegate ? ratneg(frommatr[i][j][plminusone]) : frommatr[i][j][plminusone] ;
}

void intratmatcpy(int ** frommatr, Bool bnegate,
        Bool btranspfrommatr, int nfromrows, int nfromcols, 
        Rat ** targetmatr, int targrowoffset, int targcoloffset)
{
    int i,j;
    for (i=0; i < nfromrows; i++)
        for (j=0; j < nfromcols; j++)
            if (btranspfrommatr)
                targetmatr[j + targrowoffset][i + targcoloffset]
                = ratfromi(bnegate ? -frommatr[i][j] : frommatr[i][j]);
            else
                targetmatr[i + targrowoffset][j + targcoloffset]
                = ratfromi(bnegate ? -frommatr[i][j] : frommatr[i][j]);
}

void covvector()
{
    int i, j, dim1, dim2, offset;

    behavtorealprob(1);
    behavtorealprob(2);

    dim1 = nseqs[1];
    dim2 = nseqs[2];
    offset = dim1 + 1 + nisets[2];
    /* covering vector  = -rhsq */
    for (i = 0; i < lcpdim; i++)
        vecd[i] = ratneg(rhsq[i]);
    /* first blockrow += -Aq    */
    for (i = 0; i < dim1; i++)
        for (j = 0; j < dim2; j++)
        {
            vecd[i] = ratadd(vecd[i], ratmult(lcpM[i][offset + j],
                (firstmove[2] + j)->realprob));
        }

        /* RSF yet to be done*/  
    /* third blockrow += -B\T p */
    for (i = offset; i < offset + dim2; i++)
            for (j=0; j < dim1; j++)
                vecd[i] = ratadd( vecd[i], ratmult( lcpM [i] [j],
                          (firstmove[1] + j)->realprob));
        /* RSF yet to be done*/  
}


void showeq(Bool bshortequil, int docuseed)
{
    int offset;


    offset = nseqs[1] + 1 + nisets[2];
    /*  non-sparse printing
    printf("Equilibrium realization plan player 1:\n");
    outrealplan(1, solz);
    printf("Equilibrium realization plan player 2:\n");
    outrealplan(2, solz + offset); */
    if (bshortequil)
        printf("BEQ>%4d<1>", docuseed);
    else
        printf("......Equilibrium behavior strategies player 1, 2:\n");
    outbehavstrat_moves(1, solz, !bshortequil); /* remove _moves for original code */
    if (bshortequil)
        printf(" <2>");
    outbehavstrat_moves(2, solz + offset, 1);  /* remove _moves for original code */
}

