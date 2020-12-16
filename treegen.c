/* treegen.c
 * 1 May 2001 
 * generating examples of game trees
 */

#include <stdio.h>
	/* NULL	*/
#include <stdlib.h>
        /* srand()      */
#include "rat.h"
#include "treedef.h"

#include "treegen.h"

void tracingexample(void)
{
    int pay[2][153] = {
    { 0, 1000, 125, 312, 500, 47, 109, 172, 500, 688, 47, 109, 172, 47, 109, 172, 875, 0, 1000, 125, 312, 500, 117, 180, 242, 500, 688, 117, 180, 242, 117, 180, 242, 875, 0, 1000, 125, 312, 500, 188, 250, 562, 500, 688, 188, 250, 562, 188, 250, 562, 875, 0, 1000, 125, 312, 500, 117, 180, 242, 500, 688, 117, 180, 242, 117, 180, 242, 875, 0, 1000, 125, 312, 500, 188, 250, 562, 500, 688, 188, 250, 562, 188, 250, 562, 875, 0, 1000, 125, 312, 500, 508, 570, 633, 500, 688, 508, 570, 633, 508, 570, 633, 875, 0, 1000, 125, 312, 500, 188, 250, 562, 500, 688, 188, 250, 562, 188, 250, 562, 875, 0, 1000, 125, 312, 500, 508, 570, 633, 500, 688, 508, 570, 633, 508, 570, 633, 875, 0, 1000, 125, 312, 500, 578, 641, 703, 500, 688, 578, 641, 703, 578, 641, 703, 875 },
    { 1000, 0, 875, 688, 500, 703, 641, 578, 500, 312, 703, 641, 578, 703, 641, 578, 125, 1000, 0, 875, 688, 500, 633, 570, 508, 500, 312, 633, 570, 508, 633, 570, 508, 125, 1000, 0, 875, 688, 500, 562, 500, 188, 500, 312, 562, 500, 188, 562, 500, 188, 125, 1000, 0, 875, 688, 500, 633, 570, 508, 500, 312, 633, 570, 508, 633, 570, 508, 125, 1000, 0, 875, 688, 500, 562, 500, 188, 500, 312, 562, 500, 188, 562, 500, 188, 125, 1000, 0, 875, 688, 500, 242, 180, 117, 500, 312, 242, 180, 117, 242, 180, 117, 125, 1000, 0, 875, 688, 500, 562, 500, 188, 500, 312, 562, 500, 188, 562, 500, 188, 125, 1000, 0, 875, 688, 500, 242, 180, 117, 500, 312, 242, 180, 117, 242, 180, 117, 125, 1000, 0, 875, 688, 500, 172, 109, 47, 500, 312, 172, 109, 47, 172, 109, 47, 125 }
    };
    alloctree(239, 15, 42, 153);
    Outcome z = outcomes;
    firstiset[0] = isets + 0;
    firstiset[1] = isets + 3;
    firstiset[2] = isets + 9;
    firstmove[0] = moves + 0;
    firstmove[1] = moves + 10;
    firstmove[2] = moves + 26;

    // root node is at index 1 (index 0 is skipped)
    root = nodes + ROOT;
    root->father = NULL;
    nodes[2].father = nodes + 1;

    nodes[3].father = nodes + 2;

    nodes[4].father = nodes + 3;

    nodes[5].father = nodes + 4;

    nodes[6].father = nodes + 5;

    nodes[7].father = nodes + 5;

    nodes[8].father = nodes + 7;

    nodes[9].father = nodes + 5;

    nodes[10].father = nodes + 9;

    nodes[11].father = nodes + 9;

    nodes[12].father = nodes + 2;

    nodes[13].father = nodes + 12;

    nodes[14].father = nodes + 13;

    nodes[15].father = nodes + 14;

    nodes[16].father = nodes + 14;

    nodes[17].father = nodes + 16;

    nodes[18].father = nodes + 14;

    nodes[19].father = nodes + 18;

    nodes[20].father = nodes + 18;

    nodes[21].father = nodes + 2;

    nodes[22].father = nodes + 21;

    nodes[23].father = nodes + 22;

    nodes[24].father = nodes + 23;

    nodes[25].father = nodes + 23;

    nodes[26].father = nodes + 25;

    nodes[27].father = nodes + 23;

    nodes[28].father = nodes + 27;

    nodes[29].father = nodes + 27;

    nodes[30].father = nodes + 1;

    nodes[31].father = nodes + 30;

    nodes[32].father = nodes + 31;

    nodes[33].father = nodes + 32;

    nodes[34].father = nodes + 33;

    nodes[35].father = nodes + 33;

    nodes[36].father = nodes + 35;

    nodes[37].father = nodes + 33;

    nodes[38].father = nodes + 37;

    nodes[39].father = nodes + 37;

    nodes[40].father = nodes + 30;

    nodes[41].father = nodes + 40;

    nodes[42].father = nodes + 41;

    nodes[43].father = nodes + 42;

    nodes[44].father = nodes + 42;

    nodes[45].father = nodes + 44;

    nodes[46].father = nodes + 42;

    nodes[47].father = nodes + 46;

    nodes[48].father = nodes + 46;

    nodes[49].father = nodes + 30;

    nodes[50].father = nodes + 49;

    nodes[51].father = nodes + 50;

    nodes[52].father = nodes + 51;

    nodes[53].father = nodes + 51;

    nodes[54].father = nodes + 53;

    nodes[55].father = nodes + 51;

    nodes[56].father = nodes + 55;

    nodes[57].father = nodes + 55;

    nodes[58].father = nodes + 1;

    nodes[59].father = nodes + 58;

    nodes[60].father = nodes + 59;

    nodes[61].father = nodes + 60;

    nodes[62].father = nodes + 61;

    nodes[63].father = nodes + 61;

    nodes[64].father = nodes + 63;

    nodes[65].father = nodes + 61;

    nodes[66].father = nodes + 65;

    nodes[67].father = nodes + 65;

    nodes[68].father = nodes + 58;

    nodes[69].father = nodes + 68;

    nodes[70].father = nodes + 69;

    nodes[71].father = nodes + 70;

    nodes[72].father = nodes + 70;

    nodes[73].father = nodes + 72;

    nodes[74].father = nodes + 70;

    nodes[75].father = nodes + 74;

    nodes[76].father = nodes + 74;

    nodes[77].father = nodes + 58;

    nodes[78].father = nodes + 77;

    nodes[79].father = nodes + 78;

    nodes[80].father = nodes + 79;

    nodes[81].father = nodes + 79;

    nodes[82].father = nodes + 81;

    nodes[83].father = nodes + 79;

    nodes[84].father = nodes + 83;

    nodes[85].father = nodes + 83;

    nodes[86].father = nodes + 3;

    nodes[86].terminal = 1;
    nodes[86].outcome = z;
    z->whichnode = nodes + 86;
    z->pay[0] = ratfromi(pay[0][0]);
    z->pay[1] = ratfromi(pay[1][0]);
    z++;
    nodes[87].father = nodes + 4;

    nodes[87].terminal = 1;
    nodes[87].outcome = z;
    z->whichnode = nodes + 87;
    z->pay[0] = ratfromi(pay[0][1]);
    z->pay[1] = ratfromi(pay[1][1]);
    z++;
    nodes[88].father = nodes + 6;

    nodes[88].terminal = 1;
    nodes[88].outcome = z;
    z->whichnode = nodes + 88;
    z->pay[0] = ratfromi(pay[0][2]);
    z->pay[1] = ratfromi(pay[1][2]);
    z++;
    nodes[89].father = nodes + 6;

    nodes[89].terminal = 1;
    nodes[89].outcome = z;
    z->whichnode = nodes + 89;
    z->pay[0] = ratfromi(pay[0][3]);
    z->pay[1] = ratfromi(pay[1][3]);
    z++;
    nodes[90].father = nodes + 6;

    nodes[90].terminal = 1;
    nodes[90].outcome = z;
    z->whichnode = nodes + 90;
    z->pay[0] = ratfromi(pay[0][4]);
    z->pay[1] = ratfromi(pay[1][4]);
    z++;
    nodes[91].father = nodes + 8;

    nodes[91].terminal = 1;
    nodes[91].outcome = z;
    z->whichnode = nodes + 91;
    z->pay[0] = ratfromi(pay[0][5]);
    z->pay[1] = ratfromi(pay[1][5]);
    z++;
    nodes[92].father = nodes + 8;

    nodes[92].terminal = 1;
    nodes[92].outcome = z;
    z->whichnode = nodes + 92;
    z->pay[0] = ratfromi(pay[0][6]);
    z->pay[1] = ratfromi(pay[1][6]);
    z++;
    nodes[93].father = nodes + 8;

    nodes[93].terminal = 1;
    nodes[93].outcome = z;
    z->whichnode = nodes + 93;
    z->pay[0] = ratfromi(pay[0][7]);
    z->pay[1] = ratfromi(pay[1][7]);
    z++;
    nodes[94].father = nodes + 7;

    nodes[94].terminal = 1;
    nodes[94].outcome = z;
    z->whichnode = nodes + 94;
    z->pay[0] = ratfromi(pay[0][8]);
    z->pay[1] = ratfromi(pay[1][8]);
    z++;
    nodes[95].father = nodes + 7;

    nodes[95].terminal = 1;
    nodes[95].outcome = z;
    z->whichnode = nodes + 95;
    z->pay[0] = ratfromi(pay[0][9]);
    z->pay[1] = ratfromi(pay[1][9]);
    z++;
    nodes[96].father = nodes + 10;

    nodes[96].terminal = 1;
    nodes[96].outcome = z;
    z->whichnode = nodes + 96;
    z->pay[0] = ratfromi(pay[0][10]);
    z->pay[1] = ratfromi(pay[1][10]);
    z++;
    nodes[97].father = nodes + 10;

    nodes[97].terminal = 1;
    nodes[97].outcome = z;
    z->whichnode = nodes + 97;
    z->pay[0] = ratfromi(pay[0][11]);
    z->pay[1] = ratfromi(pay[1][11]);
    z++;
    nodes[98].father = nodes + 10;

    nodes[98].terminal = 1;
    nodes[98].outcome = z;
    z->whichnode = nodes + 98;
    z->pay[0] = ratfromi(pay[0][12]);
    z->pay[1] = ratfromi(pay[1][12]);
    z++;
    nodes[99].father = nodes + 11;

    nodes[99].terminal = 1;
    nodes[99].outcome = z;
    z->whichnode = nodes + 99;
    z->pay[0] = ratfromi(pay[0][13]);
    z->pay[1] = ratfromi(pay[1][13]);
    z++;
    nodes[100].father = nodes + 11;

    nodes[100].terminal = 1;
    nodes[100].outcome = z;
    z->whichnode = nodes + 100;
    z->pay[0] = ratfromi(pay[0][14]);
    z->pay[1] = ratfromi(pay[1][14]);
    z++;
    nodes[101].father = nodes + 11;

    nodes[101].terminal = 1;
    nodes[101].outcome = z;
    z->whichnode = nodes + 101;
    z->pay[0] = ratfromi(pay[0][15]);
    z->pay[1] = ratfromi(pay[1][15]);
    z++;
    nodes[102].father = nodes + 9;

    nodes[102].terminal = 1;
    nodes[102].outcome = z;
    z->whichnode = nodes + 102;
    z->pay[0] = ratfromi(pay[0][16]);
    z->pay[1] = ratfromi(pay[1][16]);
    z++;
    nodes[103].father = nodes + 12;

    nodes[103].terminal = 1;
    nodes[103].outcome = z;
    z->whichnode = nodes + 103;
    z->pay[0] = ratfromi(pay[0][17]);
    z->pay[1] = ratfromi(pay[1][17]);
    z++;
    nodes[104].father = nodes + 13;

    nodes[104].terminal = 1;
    nodes[104].outcome = z;
    z->whichnode = nodes + 104;
    z->pay[0] = ratfromi(pay[0][18]);
    z->pay[1] = ratfromi(pay[1][18]);
    z++;
    nodes[105].father = nodes + 15;

    nodes[105].terminal = 1;
    nodes[105].outcome = z;
    z->whichnode = nodes + 105;
    z->pay[0] = ratfromi(pay[0][19]);
    z->pay[1] = ratfromi(pay[1][19]);
    z++;
    nodes[106].father = nodes + 15;

    nodes[106].terminal = 1;
    nodes[106].outcome = z;
    z->whichnode = nodes + 106;
    z->pay[0] = ratfromi(pay[0][20]);
    z->pay[1] = ratfromi(pay[1][20]);
    z++;
    nodes[107].father = nodes + 15;

    nodes[107].terminal = 1;
    nodes[107].outcome = z;
    z->whichnode = nodes + 107;
    z->pay[0] = ratfromi(pay[0][21]);
    z->pay[1] = ratfromi(pay[1][21]);
    z++;
    nodes[108].father = nodes + 17;

    nodes[108].terminal = 1;
    nodes[108].outcome = z;
    z->whichnode = nodes + 108;
    z->pay[0] = ratfromi(pay[0][22]);
    z->pay[1] = ratfromi(pay[1][22]);
    z++;
    nodes[109].father = nodes + 17;

    nodes[109].terminal = 1;
    nodes[109].outcome = z;
    z->whichnode = nodes + 109;
    z->pay[0] = ratfromi(pay[0][23]);
    z->pay[1] = ratfromi(pay[1][23]);
    z++;
    nodes[110].father = nodes + 17;

    nodes[110].terminal = 1;
    nodes[110].outcome = z;
    z->whichnode = nodes + 110;
    z->pay[0] = ratfromi(pay[0][24]);
    z->pay[1] = ratfromi(pay[1][24]);
    z++;
    nodes[111].father = nodes + 16;

    nodes[111].terminal = 1;
    nodes[111].outcome = z;
    z->whichnode = nodes + 111;
    z->pay[0] = ratfromi(pay[0][25]);
    z->pay[1] = ratfromi(pay[1][25]);
    z++;
    nodes[112].father = nodes + 16;

    nodes[112].terminal = 1;
    nodes[112].outcome = z;
    z->whichnode = nodes + 112;
    z->pay[0] = ratfromi(pay[0][26]);
    z->pay[1] = ratfromi(pay[1][26]);
    z++;
    nodes[113].father = nodes + 19;

    nodes[113].terminal = 1;
    nodes[113].outcome = z;
    z->whichnode = nodes + 113;
    z->pay[0] = ratfromi(pay[0][27]);
    z->pay[1] = ratfromi(pay[1][27]);
    z++;
    nodes[114].father = nodes + 19;

    nodes[114].terminal = 1;
    nodes[114].outcome = z;
    z->whichnode = nodes + 114;
    z->pay[0] = ratfromi(pay[0][28]);
    z->pay[1] = ratfromi(pay[1][28]);
    z++;
    nodes[115].father = nodes + 19;

    nodes[115].terminal = 1;
    nodes[115].outcome = z;
    z->whichnode = nodes + 115;
    z->pay[0] = ratfromi(pay[0][29]);
    z->pay[1] = ratfromi(pay[1][29]);
    z++;
    nodes[116].father = nodes + 20;

    nodes[116].terminal = 1;
    nodes[116].outcome = z;
    z->whichnode = nodes + 116;
    z->pay[0] = ratfromi(pay[0][30]);
    z->pay[1] = ratfromi(pay[1][30]);
    z++;
    nodes[117].father = nodes + 20;

    nodes[117].terminal = 1;
    nodes[117].outcome = z;
    z->whichnode = nodes + 117;
    z->pay[0] = ratfromi(pay[0][31]);
    z->pay[1] = ratfromi(pay[1][31]);
    z++;
    nodes[118].father = nodes + 20;

    nodes[118].terminal = 1;
    nodes[118].outcome = z;
    z->whichnode = nodes + 118;
    z->pay[0] = ratfromi(pay[0][32]);
    z->pay[1] = ratfromi(pay[1][32]);
    z++;
    nodes[119].father = nodes + 18;

    nodes[119].terminal = 1;
    nodes[119].outcome = z;
    z->whichnode = nodes + 119;
    z->pay[0] = ratfromi(pay[0][33]);
    z->pay[1] = ratfromi(pay[1][33]);
    z++;
    nodes[120].father = nodes + 21;

    nodes[120].terminal = 1;
    nodes[120].outcome = z;
    z->whichnode = nodes + 120;
    z->pay[0] = ratfromi(pay[0][34]);
    z->pay[1] = ratfromi(pay[1][34]);
    z++;
    nodes[121].father = nodes + 22;

    nodes[121].terminal = 1;
    nodes[121].outcome = z;
    z->whichnode = nodes + 121;
    z->pay[0] = ratfromi(pay[0][35]);
    z->pay[1] = ratfromi(pay[1][35]);
    z++;
    nodes[122].father = nodes + 24;

    nodes[122].terminal = 1;
    nodes[122].outcome = z;
    z->whichnode = nodes + 122;
    z->pay[0] = ratfromi(pay[0][36]);
    z->pay[1] = ratfromi(pay[1][36]);
    z++;
    nodes[123].father = nodes + 24;

    nodes[123].terminal = 1;
    nodes[123].outcome = z;
    z->whichnode = nodes + 123;
    z->pay[0] = ratfromi(pay[0][37]);
    z->pay[1] = ratfromi(pay[1][37]);
    z++;
    nodes[124].father = nodes + 24;

    nodes[124].terminal = 1;
    nodes[124].outcome = z;
    z->whichnode = nodes + 124;
    z->pay[0] = ratfromi(pay[0][38]);
    z->pay[1] = ratfromi(pay[1][38]);
    z++;
    nodes[125].father = nodes + 26;

    nodes[125].terminal = 1;
    nodes[125].outcome = z;
    z->whichnode = nodes + 125;
    z->pay[0] = ratfromi(pay[0][39]);
    z->pay[1] = ratfromi(pay[1][39]);
    z++;
    nodes[126].father = nodes + 26;

    nodes[126].terminal = 1;
    nodes[126].outcome = z;
    z->whichnode = nodes + 126;
    z->pay[0] = ratfromi(pay[0][40]);
    z->pay[1] = ratfromi(pay[1][40]);
    z++;
    nodes[127].father = nodes + 26;

    nodes[127].terminal = 1;
    nodes[127].outcome = z;
    z->whichnode = nodes + 127;
    z->pay[0] = ratfromi(pay[0][41]);
    z->pay[1] = ratfromi(pay[1][41]);
    z++;
    nodes[128].father = nodes + 25;

    nodes[128].terminal = 1;
    nodes[128].outcome = z;
    z->whichnode = nodes + 128;
    z->pay[0] = ratfromi(pay[0][42]);
    z->pay[1] = ratfromi(pay[1][42]);
    z++;
    nodes[129].father = nodes + 25;

    nodes[129].terminal = 1;
    nodes[129].outcome = z;
    z->whichnode = nodes + 129;
    z->pay[0] = ratfromi(pay[0][43]);
    z->pay[1] = ratfromi(pay[1][43]);
    z++;
    nodes[130].father = nodes + 28;

    nodes[130].terminal = 1;
    nodes[130].outcome = z;
    z->whichnode = nodes + 130;
    z->pay[0] = ratfromi(pay[0][44]);
    z->pay[1] = ratfromi(pay[1][44]);
    z++;
    nodes[131].father = nodes + 28;

    nodes[131].terminal = 1;
    nodes[131].outcome = z;
    z->whichnode = nodes + 131;
    z->pay[0] = ratfromi(pay[0][45]);
    z->pay[1] = ratfromi(pay[1][45]);
    z++;
    nodes[132].father = nodes + 28;

    nodes[132].terminal = 1;
    nodes[132].outcome = z;
    z->whichnode = nodes + 132;
    z->pay[0] = ratfromi(pay[0][46]);
    z->pay[1] = ratfromi(pay[1][46]);
    z++;
    nodes[133].father = nodes + 29;

    nodes[133].terminal = 1;
    nodes[133].outcome = z;
    z->whichnode = nodes + 133;
    z->pay[0] = ratfromi(pay[0][47]);
    z->pay[1] = ratfromi(pay[1][47]);
    z++;
    nodes[134].father = nodes + 29;

    nodes[134].terminal = 1;
    nodes[134].outcome = z;
    z->whichnode = nodes + 134;
    z->pay[0] = ratfromi(pay[0][48]);
    z->pay[1] = ratfromi(pay[1][48]);
    z++;
    nodes[135].father = nodes + 29;

    nodes[135].terminal = 1;
    nodes[135].outcome = z;
    z->whichnode = nodes + 135;
    z->pay[0] = ratfromi(pay[0][49]);
    z->pay[1] = ratfromi(pay[1][49]);
    z++;
    nodes[136].father = nodes + 27;

    nodes[136].terminal = 1;
    nodes[136].outcome = z;
    z->whichnode = nodes + 136;
    z->pay[0] = ratfromi(pay[0][50]);
    z->pay[1] = ratfromi(pay[1][50]);
    z++;
    nodes[137].father = nodes + 31;

    nodes[137].terminal = 1;
    nodes[137].outcome = z;
    z->whichnode = nodes + 137;
    z->pay[0] = ratfromi(pay[0][51]);
    z->pay[1] = ratfromi(pay[1][51]);
    z++;
    nodes[138].father = nodes + 32;

    nodes[138].terminal = 1;
    nodes[138].outcome = z;
    z->whichnode = nodes + 138;
    z->pay[0] = ratfromi(pay[0][52]);
    z->pay[1] = ratfromi(pay[1][52]);
    z++;
    nodes[139].father = nodes + 34;

    nodes[139].terminal = 1;
    nodes[139].outcome = z;
    z->whichnode = nodes + 139;
    z->pay[0] = ratfromi(pay[0][53]);
    z->pay[1] = ratfromi(pay[1][53]);
    z++;
    nodes[140].father = nodes + 34;

    nodes[140].terminal = 1;
    nodes[140].outcome = z;
    z->whichnode = nodes + 140;
    z->pay[0] = ratfromi(pay[0][54]);
    z->pay[1] = ratfromi(pay[1][54]);
    z++;
    nodes[141].father = nodes + 34;

    nodes[141].terminal = 1;
    nodes[141].outcome = z;
    z->whichnode = nodes + 141;
    z->pay[0] = ratfromi(pay[0][55]);
    z->pay[1] = ratfromi(pay[1][55]);
    z++;
    nodes[142].father = nodes + 36;

    nodes[142].terminal = 1;
    nodes[142].outcome = z;
    z->whichnode = nodes + 142;
    z->pay[0] = ratfromi(pay[0][56]);
    z->pay[1] = ratfromi(pay[1][56]);
    z++;
    nodes[143].father = nodes + 36;

    nodes[143].terminal = 1;
    nodes[143].outcome = z;
    z->whichnode = nodes + 143;
    z->pay[0] = ratfromi(pay[0][57]);
    z->pay[1] = ratfromi(pay[1][57]);
    z++;
    nodes[144].father = nodes + 36;

    nodes[144].terminal = 1;
    nodes[144].outcome = z;
    z->whichnode = nodes + 144;
    z->pay[0] = ratfromi(pay[0][58]);
    z->pay[1] = ratfromi(pay[1][58]);
    z++;
    nodes[145].father = nodes + 35;

    nodes[145].terminal = 1;
    nodes[145].outcome = z;
    z->whichnode = nodes + 145;
    z->pay[0] = ratfromi(pay[0][59]);
    z->pay[1] = ratfromi(pay[1][59]);
    z++;
    nodes[146].father = nodes + 35;

    nodes[146].terminal = 1;
    nodes[146].outcome = z;
    z->whichnode = nodes + 146;
    z->pay[0] = ratfromi(pay[0][60]);
    z->pay[1] = ratfromi(pay[1][60]);
    z++;
    nodes[147].father = nodes + 38;

    nodes[147].terminal = 1;
    nodes[147].outcome = z;
    z->whichnode = nodes + 147;
    z->pay[0] = ratfromi(pay[0][61]);
    z->pay[1] = ratfromi(pay[1][61]);
    z++;
    nodes[148].father = nodes + 38;

    nodes[148].terminal = 1;
    nodes[148].outcome = z;
    z->whichnode = nodes + 148;
    z->pay[0] = ratfromi(pay[0][62]);
    z->pay[1] = ratfromi(pay[1][62]);
    z++;
    nodes[149].father = nodes + 38;

    nodes[149].terminal = 1;
    nodes[149].outcome = z;
    z->whichnode = nodes + 149;
    z->pay[0] = ratfromi(pay[0][63]);
    z->pay[1] = ratfromi(pay[1][63]);
    z++;
    nodes[150].father = nodes + 39;

    nodes[150].terminal = 1;
    nodes[150].outcome = z;
    z->whichnode = nodes + 150;
    z->pay[0] = ratfromi(pay[0][64]);
    z->pay[1] = ratfromi(pay[1][64]);
    z++;
    nodes[151].father = nodes + 39;

    nodes[151].terminal = 1;
    nodes[151].outcome = z;
    z->whichnode = nodes + 151;
    z->pay[0] = ratfromi(pay[0][65]);
    z->pay[1] = ratfromi(pay[1][65]);
    z++;
    nodes[152].father = nodes + 39;

    nodes[152].terminal = 1;
    nodes[152].outcome = z;
    z->whichnode = nodes + 152;
    z->pay[0] = ratfromi(pay[0][66]);
    z->pay[1] = ratfromi(pay[1][66]);
    z++;
    nodes[153].father = nodes + 37;

    nodes[153].terminal = 1;
    nodes[153].outcome = z;
    z->whichnode = nodes + 153;
    z->pay[0] = ratfromi(pay[0][67]);
    z->pay[1] = ratfromi(pay[1][67]);
    z++;
    nodes[154].father = nodes + 40;

    nodes[154].terminal = 1;
    nodes[154].outcome = z;
    z->whichnode = nodes + 154;
    z->pay[0] = ratfromi(pay[0][68]);
    z->pay[1] = ratfromi(pay[1][68]);
    z++;
    nodes[155].father = nodes + 41;

    nodes[155].terminal = 1;
    nodes[155].outcome = z;
    z->whichnode = nodes + 155;
    z->pay[0] = ratfromi(pay[0][69]);
    z->pay[1] = ratfromi(pay[1][69]);
    z++;
    nodes[156].father = nodes + 43;

    nodes[156].terminal = 1;
    nodes[156].outcome = z;
    z->whichnode = nodes + 156;
    z->pay[0] = ratfromi(pay[0][70]);
    z->pay[1] = ratfromi(pay[1][70]);
    z++;
    nodes[157].father = nodes + 43;

    nodes[157].terminal = 1;
    nodes[157].outcome = z;
    z->whichnode = nodes + 157;
    z->pay[0] = ratfromi(pay[0][71]);
    z->pay[1] = ratfromi(pay[1][71]);
    z++;
    nodes[158].father = nodes + 43;

    nodes[158].terminal = 1;
    nodes[158].outcome = z;
    z->whichnode = nodes + 158;
    z->pay[0] = ratfromi(pay[0][72]);
    z->pay[1] = ratfromi(pay[1][72]);
    z++;
    nodes[159].father = nodes + 45;

    nodes[159].terminal = 1;
    nodes[159].outcome = z;
    z->whichnode = nodes + 159;
    z->pay[0] = ratfromi(pay[0][73]);
    z->pay[1] = ratfromi(pay[1][73]);
    z++;
    nodes[160].father = nodes + 45;

    nodes[160].terminal = 1;
    nodes[160].outcome = z;
    z->whichnode = nodes + 160;
    z->pay[0] = ratfromi(pay[0][74]);
    z->pay[1] = ratfromi(pay[1][74]);
    z++;
    nodes[161].father = nodes + 45;

    nodes[161].terminal = 1;
    nodes[161].outcome = z;
    z->whichnode = nodes + 161;
    z->pay[0] = ratfromi(pay[0][75]);
    z->pay[1] = ratfromi(pay[1][75]);
    z++;
    nodes[162].father = nodes + 44;

    nodes[162].terminal = 1;
    nodes[162].outcome = z;
    z->whichnode = nodes + 162;
    z->pay[0] = ratfromi(pay[0][76]);
    z->pay[1] = ratfromi(pay[1][76]);
    z++;
    nodes[163].father = nodes + 44;

    nodes[163].terminal = 1;
    nodes[163].outcome = z;
    z->whichnode = nodes + 163;
    z->pay[0] = ratfromi(pay[0][77]);
    z->pay[1] = ratfromi(pay[1][77]);
    z++;
    nodes[164].father = nodes + 47;

    nodes[164].terminal = 1;
    nodes[164].outcome = z;
    z->whichnode = nodes + 164;
    z->pay[0] = ratfromi(pay[0][78]);
    z->pay[1] = ratfromi(pay[1][78]);
    z++;
    nodes[165].father = nodes + 47;

    nodes[165].terminal = 1;
    nodes[165].outcome = z;
    z->whichnode = nodes + 165;
    z->pay[0] = ratfromi(pay[0][79]);
    z->pay[1] = ratfromi(pay[1][79]);
    z++;
    nodes[166].father = nodes + 47;

    nodes[166].terminal = 1;
    nodes[166].outcome = z;
    z->whichnode = nodes + 166;
    z->pay[0] = ratfromi(pay[0][80]);
    z->pay[1] = ratfromi(pay[1][80]);
    z++;
    nodes[167].father = nodes + 48;

    nodes[167].terminal = 1;
    nodes[167].outcome = z;
    z->whichnode = nodes + 167;
    z->pay[0] = ratfromi(pay[0][81]);
    z->pay[1] = ratfromi(pay[1][81]);
    z++;
    nodes[168].father = nodes + 48;

    nodes[168].terminal = 1;
    nodes[168].outcome = z;
    z->whichnode = nodes + 168;
    z->pay[0] = ratfromi(pay[0][82]);
    z->pay[1] = ratfromi(pay[1][82]);
    z++;
    nodes[169].father = nodes + 48;

    nodes[169].terminal = 1;
    nodes[169].outcome = z;
    z->whichnode = nodes + 169;
    z->pay[0] = ratfromi(pay[0][83]);
    z->pay[1] = ratfromi(pay[1][83]);
    z++;
    nodes[170].father = nodes + 46;

    nodes[170].terminal = 1;
    nodes[170].outcome = z;
    z->whichnode = nodes + 170;
    z->pay[0] = ratfromi(pay[0][84]);
    z->pay[1] = ratfromi(pay[1][84]);
    z++;
    nodes[171].father = nodes + 49;

    nodes[171].terminal = 1;
    nodes[171].outcome = z;
    z->whichnode = nodes + 171;
    z->pay[0] = ratfromi(pay[0][85]);
    z->pay[1] = ratfromi(pay[1][85]);
    z++;
    nodes[172].father = nodes + 50;

    nodes[172].terminal = 1;
    nodes[172].outcome = z;
    z->whichnode = nodes + 172;
    z->pay[0] = ratfromi(pay[0][86]);
    z->pay[1] = ratfromi(pay[1][86]);
    z++;
    nodes[173].father = nodes + 52;

    nodes[173].terminal = 1;
    nodes[173].outcome = z;
    z->whichnode = nodes + 173;
    z->pay[0] = ratfromi(pay[0][87]);
    z->pay[1] = ratfromi(pay[1][87]);
    z++;
    nodes[174].father = nodes + 52;

    nodes[174].terminal = 1;
    nodes[174].outcome = z;
    z->whichnode = nodes + 174;
    z->pay[0] = ratfromi(pay[0][88]);
    z->pay[1] = ratfromi(pay[1][88]);
    z++;
    nodes[175].father = nodes + 52;

    nodes[175].terminal = 1;
    nodes[175].outcome = z;
    z->whichnode = nodes + 175;
    z->pay[0] = ratfromi(pay[0][89]);
    z->pay[1] = ratfromi(pay[1][89]);
    z++;
    nodes[176].father = nodes + 54;

    nodes[176].terminal = 1;
    nodes[176].outcome = z;
    z->whichnode = nodes + 176;
    z->pay[0] = ratfromi(pay[0][90]);
    z->pay[1] = ratfromi(pay[1][90]);
    z++;
    nodes[177].father = nodes + 54;

    nodes[177].terminal = 1;
    nodes[177].outcome = z;
    z->whichnode = nodes + 177;
    z->pay[0] = ratfromi(pay[0][91]);
    z->pay[1] = ratfromi(pay[1][91]);
    z++;
    nodes[178].father = nodes + 54;

    nodes[178].terminal = 1;
    nodes[178].outcome = z;
    z->whichnode = nodes + 178;
    z->pay[0] = ratfromi(pay[0][92]);
    z->pay[1] = ratfromi(pay[1][92]);
    z++;
    nodes[179].father = nodes + 53;

    nodes[179].terminal = 1;
    nodes[179].outcome = z;
    z->whichnode = nodes + 179;
    z->pay[0] = ratfromi(pay[0][93]);
    z->pay[1] = ratfromi(pay[1][93]);
    z++;
    nodes[180].father = nodes + 53;

    nodes[180].terminal = 1;
    nodes[180].outcome = z;
    z->whichnode = nodes + 180;
    z->pay[0] = ratfromi(pay[0][94]);
    z->pay[1] = ratfromi(pay[1][94]);
    z++;
    nodes[181].father = nodes + 56;

    nodes[181].terminal = 1;
    nodes[181].outcome = z;
    z->whichnode = nodes + 181;
    z->pay[0] = ratfromi(pay[0][95]);
    z->pay[1] = ratfromi(pay[1][95]);
    z++;
    nodes[182].father = nodes + 56;

    nodes[182].terminal = 1;
    nodes[182].outcome = z;
    z->whichnode = nodes + 182;
    z->pay[0] = ratfromi(pay[0][96]);
    z->pay[1] = ratfromi(pay[1][96]);
    z++;
    nodes[183].father = nodes + 56;

    nodes[183].terminal = 1;
    nodes[183].outcome = z;
    z->whichnode = nodes + 183;
    z->pay[0] = ratfromi(pay[0][97]);
    z->pay[1] = ratfromi(pay[1][97]);
    z++;
    nodes[184].father = nodes + 57;

    nodes[184].terminal = 1;
    nodes[184].outcome = z;
    z->whichnode = nodes + 184;
    z->pay[0] = ratfromi(pay[0][98]);
    z->pay[1] = ratfromi(pay[1][98]);
    z++;
    nodes[185].father = nodes + 57;

    nodes[185].terminal = 1;
    nodes[185].outcome = z;
    z->whichnode = nodes + 185;
    z->pay[0] = ratfromi(pay[0][99]);
    z->pay[1] = ratfromi(pay[1][99]);
    z++;
    nodes[186].father = nodes + 57;

    nodes[186].terminal = 1;
    nodes[186].outcome = z;
    z->whichnode = nodes + 186;
    z->pay[0] = ratfromi(pay[0][100]);
    z->pay[1] = ratfromi(pay[1][100]);
    z++;
    nodes[187].father = nodes + 55;

    nodes[187].terminal = 1;
    nodes[187].outcome = z;
    z->whichnode = nodes + 187;
    z->pay[0] = ratfromi(pay[0][101]);
    z->pay[1] = ratfromi(pay[1][101]);
    z++;
    nodes[188].father = nodes + 59;

    nodes[188].terminal = 1;
    nodes[188].outcome = z;
    z->whichnode = nodes + 188;
    z->pay[0] = ratfromi(pay[0][102]);
    z->pay[1] = ratfromi(pay[1][102]);
    z++;
    nodes[189].father = nodes + 60;

    nodes[189].terminal = 1;
    nodes[189].outcome = z;
    z->whichnode = nodes + 189;
    z->pay[0] = ratfromi(pay[0][103]);
    z->pay[1] = ratfromi(pay[1][103]);
    z++;
    nodes[190].father = nodes + 62;

    nodes[190].terminal = 1;
    nodes[190].outcome = z;
    z->whichnode = nodes + 190;
    z->pay[0] = ratfromi(pay[0][104]);
    z->pay[1] = ratfromi(pay[1][104]);
    z++;
    nodes[191].father = nodes + 62;

    nodes[191].terminal = 1;
    nodes[191].outcome = z;
    z->whichnode = nodes + 191;
    z->pay[0] = ratfromi(pay[0][105]);
    z->pay[1] = ratfromi(pay[1][105]);
    z++;
    nodes[192].father = nodes + 62;

    nodes[192].terminal = 1;
    nodes[192].outcome = z;
    z->whichnode = nodes + 192;
    z->pay[0] = ratfromi(pay[0][106]);
    z->pay[1] = ratfromi(pay[1][106]);
    z++;
    nodes[193].father = nodes + 64;

    nodes[193].terminal = 1;
    nodes[193].outcome = z;
    z->whichnode = nodes + 193;
    z->pay[0] = ratfromi(pay[0][107]);
    z->pay[1] = ratfromi(pay[1][107]);
    z++;
    nodes[194].father = nodes + 64;

    nodes[194].terminal = 1;
    nodes[194].outcome = z;
    z->whichnode = nodes + 194;
    z->pay[0] = ratfromi(pay[0][108]);
    z->pay[1] = ratfromi(pay[1][108]);
    z++;
    nodes[195].father = nodes + 64;

    nodes[195].terminal = 1;
    nodes[195].outcome = z;
    z->whichnode = nodes + 195;
    z->pay[0] = ratfromi(pay[0][109]);
    z->pay[1] = ratfromi(pay[1][109]);
    z++;
    nodes[196].father = nodes + 63;

    nodes[196].terminal = 1;
    nodes[196].outcome = z;
    z->whichnode = nodes + 196;
    z->pay[0] = ratfromi(pay[0][110]);
    z->pay[1] = ratfromi(pay[1][110]);
    z++;
    nodes[197].father = nodes + 63;

    nodes[197].terminal = 1;
    nodes[197].outcome = z;
    z->whichnode = nodes + 197;
    z->pay[0] = ratfromi(pay[0][111]);
    z->pay[1] = ratfromi(pay[1][111]);
    z++;
    nodes[198].father = nodes + 66;

    nodes[198].terminal = 1;
    nodes[198].outcome = z;
    z->whichnode = nodes + 198;
    z->pay[0] = ratfromi(pay[0][112]);
    z->pay[1] = ratfromi(pay[1][112]);
    z++;
    nodes[199].father = nodes + 66;

    nodes[199].terminal = 1;
    nodes[199].outcome = z;
    z->whichnode = nodes + 199;
    z->pay[0] = ratfromi(pay[0][113]);
    z->pay[1] = ratfromi(pay[1][113]);
    z++;
    nodes[200].father = nodes + 66;

    nodes[200].terminal = 1;
    nodes[200].outcome = z;
    z->whichnode = nodes + 200;
    z->pay[0] = ratfromi(pay[0][114]);
    z->pay[1] = ratfromi(pay[1][114]);
    z++;
    nodes[201].father = nodes + 67;

    nodes[201].terminal = 1;
    nodes[201].outcome = z;
    z->whichnode = nodes + 201;
    z->pay[0] = ratfromi(pay[0][115]);
    z->pay[1] = ratfromi(pay[1][115]);
    z++;
    nodes[202].father = nodes + 67;

    nodes[202].terminal = 1;
    nodes[202].outcome = z;
    z->whichnode = nodes + 202;
    z->pay[0] = ratfromi(pay[0][116]);
    z->pay[1] = ratfromi(pay[1][116]);
    z++;
    nodes[203].father = nodes + 67;

    nodes[203].terminal = 1;
    nodes[203].outcome = z;
    z->whichnode = nodes + 203;
    z->pay[0] = ratfromi(pay[0][117]);
    z->pay[1] = ratfromi(pay[1][117]);
    z++;
    nodes[204].father = nodes + 65;

    nodes[204].terminal = 1;
    nodes[204].outcome = z;
    z->whichnode = nodes + 204;
    z->pay[0] = ratfromi(pay[0][118]);
    z->pay[1] = ratfromi(pay[1][118]);
    z++;
    nodes[205].father = nodes + 68;

    nodes[205].terminal = 1;
    nodes[205].outcome = z;
    z->whichnode = nodes + 205;
    z->pay[0] = ratfromi(pay[0][119]);
    z->pay[1] = ratfromi(pay[1][119]);
    z++;
    nodes[206].father = nodes + 69;

    nodes[206].terminal = 1;
    nodes[206].outcome = z;
    z->whichnode = nodes + 206;
    z->pay[0] = ratfromi(pay[0][120]);
    z->pay[1] = ratfromi(pay[1][120]);
    z++;
    nodes[207].father = nodes + 71;

    nodes[207].terminal = 1;
    nodes[207].outcome = z;
    z->whichnode = nodes + 207;
    z->pay[0] = ratfromi(pay[0][121]);
    z->pay[1] = ratfromi(pay[1][121]);
    z++;
    nodes[208].father = nodes + 71;

    nodes[208].terminal = 1;
    nodes[208].outcome = z;
    z->whichnode = nodes + 208;
    z->pay[0] = ratfromi(pay[0][122]);
    z->pay[1] = ratfromi(pay[1][122]);
    z++;
    nodes[209].father = nodes + 71;

    nodes[209].terminal = 1;
    nodes[209].outcome = z;
    z->whichnode = nodes + 209;
    z->pay[0] = ratfromi(pay[0][123]);
    z->pay[1] = ratfromi(pay[1][123]);
    z++;
    nodes[210].father = nodes + 73;

    nodes[210].terminal = 1;
    nodes[210].outcome = z;
    z->whichnode = nodes + 210;
    z->pay[0] = ratfromi(pay[0][124]);
    z->pay[1] = ratfromi(pay[1][124]);
    z++;
    nodes[211].father = nodes + 73;

    nodes[211].terminal = 1;
    nodes[211].outcome = z;
    z->whichnode = nodes + 211;
    z->pay[0] = ratfromi(pay[0][125]);
    z->pay[1] = ratfromi(pay[1][125]);
    z++;
    nodes[212].father = nodes + 73;

    nodes[212].terminal = 1;
    nodes[212].outcome = z;
    z->whichnode = nodes + 212;
    z->pay[0] = ratfromi(pay[0][126]);
    z->pay[1] = ratfromi(pay[1][126]);
    z++;
    nodes[213].father = nodes + 72;

    nodes[213].terminal = 1;
    nodes[213].outcome = z;
    z->whichnode = nodes + 213;
    z->pay[0] = ratfromi(pay[0][127]);
    z->pay[1] = ratfromi(pay[1][127]);
    z++;
    nodes[214].father = nodes + 72;

    nodes[214].terminal = 1;
    nodes[214].outcome = z;
    z->whichnode = nodes + 214;
    z->pay[0] = ratfromi(pay[0][128]);
    z->pay[1] = ratfromi(pay[1][128]);
    z++;
    nodes[215].father = nodes + 75;

    nodes[215].terminal = 1;
    nodes[215].outcome = z;
    z->whichnode = nodes + 215;
    z->pay[0] = ratfromi(pay[0][129]);
    z->pay[1] = ratfromi(pay[1][129]);
    z++;
    nodes[216].father = nodes + 75;

    nodes[216].terminal = 1;
    nodes[216].outcome = z;
    z->whichnode = nodes + 216;
    z->pay[0] = ratfromi(pay[0][130]);
    z->pay[1] = ratfromi(pay[1][130]);
    z++;
    nodes[217].father = nodes + 75;

    nodes[217].terminal = 1;
    nodes[217].outcome = z;
    z->whichnode = nodes + 217;
    z->pay[0] = ratfromi(pay[0][131]);
    z->pay[1] = ratfromi(pay[1][131]);
    z++;
    nodes[218].father = nodes + 76;

    nodes[218].terminal = 1;
    nodes[218].outcome = z;
    z->whichnode = nodes + 218;
    z->pay[0] = ratfromi(pay[0][132]);
    z->pay[1] = ratfromi(pay[1][132]);
    z++;
    nodes[219].father = nodes + 76;

    nodes[219].terminal = 1;
    nodes[219].outcome = z;
    z->whichnode = nodes + 219;
    z->pay[0] = ratfromi(pay[0][133]);
    z->pay[1] = ratfromi(pay[1][133]);
    z++;
    nodes[220].father = nodes + 76;

    nodes[220].terminal = 1;
    nodes[220].outcome = z;
    z->whichnode = nodes + 220;
    z->pay[0] = ratfromi(pay[0][134]);
    z->pay[1] = ratfromi(pay[1][134]);
    z++;
    nodes[221].father = nodes + 74;

    nodes[221].terminal = 1;
    nodes[221].outcome = z;
    z->whichnode = nodes + 221;
    z->pay[0] = ratfromi(pay[0][135]);
    z->pay[1] = ratfromi(pay[1][135]);
    z++;
    nodes[222].father = nodes + 77;

    nodes[222].terminal = 1;
    nodes[222].outcome = z;
    z->whichnode = nodes + 222;
    z->pay[0] = ratfromi(pay[0][136]);
    z->pay[1] = ratfromi(pay[1][136]);
    z++;
    nodes[223].father = nodes + 78;

    nodes[223].terminal = 1;
    nodes[223].outcome = z;
    z->whichnode = nodes + 223;
    z->pay[0] = ratfromi(pay[0][137]);
    z->pay[1] = ratfromi(pay[1][137]);
    z++;
    nodes[224].father = nodes + 80;

    nodes[224].terminal = 1;
    nodes[224].outcome = z;
    z->whichnode = nodes + 224;
    z->pay[0] = ratfromi(pay[0][138]);
    z->pay[1] = ratfromi(pay[1][138]);
    z++;
    nodes[225].father = nodes + 80;

    nodes[225].terminal = 1;
    nodes[225].outcome = z;
    z->whichnode = nodes + 225;
    z->pay[0] = ratfromi(pay[0][139]);
    z->pay[1] = ratfromi(pay[1][139]);
    z++;
    nodes[226].father = nodes + 80;

    nodes[226].terminal = 1;
    nodes[226].outcome = z;
    z->whichnode = nodes + 226;
    z->pay[0] = ratfromi(pay[0][140]);
    z->pay[1] = ratfromi(pay[1][140]);
    z++;
    nodes[227].father = nodes + 82;

    nodes[227].terminal = 1;
    nodes[227].outcome = z;
    z->whichnode = nodes + 227;
    z->pay[0] = ratfromi(pay[0][141]);
    z->pay[1] = ratfromi(pay[1][141]);
    z++;
    nodes[228].father = nodes + 82;

    nodes[228].terminal = 1;
    nodes[228].outcome = z;
    z->whichnode = nodes + 228;
    z->pay[0] = ratfromi(pay[0][142]);
    z->pay[1] = ratfromi(pay[1][142]);
    z++;
    nodes[229].father = nodes + 82;

    nodes[229].terminal = 1;
    nodes[229].outcome = z;
    z->whichnode = nodes + 229;
    z->pay[0] = ratfromi(pay[0][143]);
    z->pay[1] = ratfromi(pay[1][143]);
    z++;
    nodes[230].father = nodes + 81;

    nodes[230].terminal = 1;
    nodes[230].outcome = z;
    z->whichnode = nodes + 230;
    z->pay[0] = ratfromi(pay[0][144]);
    z->pay[1] = ratfromi(pay[1][144]);
    z++;
    nodes[231].father = nodes + 81;

    nodes[231].terminal = 1;
    nodes[231].outcome = z;
    z->whichnode = nodes + 231;
    z->pay[0] = ratfromi(pay[0][145]);
    z->pay[1] = ratfromi(pay[1][145]);
    z++;
    nodes[232].father = nodes + 84;

    nodes[232].terminal = 1;
    nodes[232].outcome = z;
    z->whichnode = nodes + 232;
    z->pay[0] = ratfromi(pay[0][146]);
    z->pay[1] = ratfromi(pay[1][146]);
    z++;
    nodes[233].father = nodes + 84;

    nodes[233].terminal = 1;
    nodes[233].outcome = z;
    z->whichnode = nodes + 233;
    z->pay[0] = ratfromi(pay[0][147]);
    z->pay[1] = ratfromi(pay[1][147]);
    z++;
    nodes[234].father = nodes + 84;

    nodes[234].terminal = 1;
    nodes[234].outcome = z;
    z->whichnode = nodes + 234;
    z->pay[0] = ratfromi(pay[0][148]);
    z->pay[1] = ratfromi(pay[1][148]);
    z++;
    nodes[235].father = nodes + 85;

    nodes[235].terminal = 1;
    nodes[235].outcome = z;
    z->whichnode = nodes + 235;
    z->pay[0] = ratfromi(pay[0][149]);
    z->pay[1] = ratfromi(pay[1][149]);
    z++;
    nodes[236].father = nodes + 85;

    nodes[236].terminal = 1;
    nodes[236].outcome = z;
    z->whichnode = nodes + 236;
    z->pay[0] = ratfromi(pay[0][150]);
    z->pay[1] = ratfromi(pay[1][150]);
    z++;
    nodes[237].father = nodes + 85;

    nodes[237].terminal = 1;
    nodes[237].outcome = z;
    z->whichnode = nodes + 237;
    z->pay[0] = ratfromi(pay[0][151]);
    z->pay[1] = ratfromi(pay[1][151]);
    z++;
    nodes[238].father = nodes + 83;

    nodes[238].terminal = 1;
    nodes[238].outcome = z;
    z->whichnode = nodes + 238;
    z->pay[0] = ratfromi(pay[0][152]);
    z->pay[1] = ratfromi(pay[1][152]);
    z++;
    nodes[1].iset = isets + 0;
    nodes[2].iset = isets + 1;
    nodes[3].iset = isets + 3;
    nodes[4].iset = isets + 9;
    nodes[5].iset = isets + 4;
    nodes[6].iset = isets + 10;
    nodes[7].iset = isets + 10;
    nodes[8].iset = isets + 2;
    nodes[9].iset = isets + 10;
    nodes[10].iset = isets + 2;
    nodes[11].iset = isets + 2;
    nodes[12].iset = isets + 3;
    nodes[13].iset = isets + 11;
    nodes[14].iset = isets + 4;
    nodes[15].iset = isets + 12;
    nodes[16].iset = isets + 12;
    nodes[17].iset = isets + 2;
    nodes[18].iset = isets + 12;
    nodes[19].iset = isets + 2;
    nodes[20].iset = isets + 2;
    nodes[21].iset = isets + 3;
    nodes[22].iset = isets + 13;
    nodes[23].iset = isets + 4;
    nodes[24].iset = isets + 14;
    nodes[25].iset = isets + 14;
    nodes[26].iset = isets + 2;
    nodes[27].iset = isets + 14;
    nodes[28].iset = isets + 2;
    nodes[29].iset = isets + 2;
    nodes[30].iset = isets + 1;
    nodes[31].iset = isets + 5;
    nodes[32].iset = isets + 9;
    nodes[33].iset = isets + 6;
    nodes[34].iset = isets + 10;
    nodes[35].iset = isets + 10;
    nodes[36].iset = isets + 2;
    nodes[37].iset = isets + 10;
    nodes[38].iset = isets + 2;
    nodes[39].iset = isets + 2;
    nodes[40].iset = isets + 5;
    nodes[41].iset = isets + 11;
    nodes[42].iset = isets + 6;
    nodes[43].iset = isets + 12;
    nodes[44].iset = isets + 12;
    nodes[45].iset = isets + 2;
    nodes[46].iset = isets + 12;
    nodes[47].iset = isets + 2;
    nodes[48].iset = isets + 2;
    nodes[49].iset = isets + 5;
    nodes[50].iset = isets + 13;
    nodes[51].iset = isets + 6;
    nodes[52].iset = isets + 14;
    nodes[53].iset = isets + 14;
    nodes[54].iset = isets + 2;
    nodes[55].iset = isets + 14;
    nodes[56].iset = isets + 2;
    nodes[57].iset = isets + 2;
    nodes[58].iset = isets + 1;
    nodes[59].iset = isets + 7;
    nodes[60].iset = isets + 9;
    nodes[61].iset = isets + 8;
    nodes[62].iset = isets + 10;
    nodes[63].iset = isets + 10;
    nodes[64].iset = isets + 2;
    nodes[65].iset = isets + 10;
    nodes[66].iset = isets + 2;
    nodes[67].iset = isets + 2;
    nodes[68].iset = isets + 7;
    nodes[69].iset = isets + 11;
    nodes[70].iset = isets + 8;
    nodes[71].iset = isets + 12;
    nodes[72].iset = isets + 12;
    nodes[73].iset = isets + 2;
    nodes[74].iset = isets + 12;
    nodes[75].iset = isets + 2;
    nodes[76].iset = isets + 2;
    nodes[77].iset = isets + 7;
    nodes[78].iset = isets + 13;
    nodes[79].iset = isets + 8;
    nodes[80].iset = isets + 14;
    nodes[81].iset = isets + 14;
    nodes[82].iset = isets + 2;
    nodes[83].iset = isets + 14;
    nodes[84].iset = isets + 2;
    nodes[85].iset = isets + 2;
    nodes[2].reachedby = moves + 1;
    nodes[3].reachedby = moves + 4;
    nodes[4].reachedby = moves + 12;
    nodes[5].reachedby = moves + 28;
    nodes[6].reachedby = moves + 13;
    nodes[7].reachedby = moves + 14;
    nodes[8].reachedby = moves + 29;
    nodes[9].reachedby = moves + 15;
    nodes[10].reachedby = moves + 29;
    nodes[11].reachedby = moves + 30;
    nodes[12].reachedby = moves + 5;
    nodes[13].reachedby = moves + 12;
    nodes[14].reachedby = moves + 33;
    nodes[15].reachedby = moves + 13;
    nodes[16].reachedby = moves + 14;
    nodes[17].reachedby = moves + 34;
    nodes[18].reachedby = moves + 15;
    nodes[19].reachedby = moves + 34;
    nodes[20].reachedby = moves + 35;
    nodes[21].reachedby = moves + 6;
    nodes[22].reachedby = moves + 12;
    nodes[23].reachedby = moves + 38;
    nodes[24].reachedby = moves + 13;
    nodes[25].reachedby = moves + 14;
    nodes[26].reachedby = moves + 39;
    nodes[27].reachedby = moves + 15;
    nodes[28].reachedby = moves + 39;
    nodes[29].reachedby = moves + 40;
    nodes[30].reachedby = moves + 2;
    nodes[31].reachedby = moves + 4;
    nodes[32].reachedby = moves + 17;
    nodes[33].reachedby = moves + 28;
    nodes[34].reachedby = moves + 18;
    nodes[35].reachedby = moves + 19;
    nodes[36].reachedby = moves + 29;
    nodes[37].reachedby = moves + 20;
    nodes[38].reachedby = moves + 29;
    nodes[39].reachedby = moves + 30;
    nodes[40].reachedby = moves + 5;
    nodes[41].reachedby = moves + 17;
    nodes[42].reachedby = moves + 33;
    nodes[43].reachedby = moves + 18;
    nodes[44].reachedby = moves + 19;
    nodes[45].reachedby = moves + 34;
    nodes[46].reachedby = moves + 20;
    nodes[47].reachedby = moves + 34;
    nodes[48].reachedby = moves + 35;
    nodes[49].reachedby = moves + 6;
    nodes[50].reachedby = moves + 17;
    nodes[51].reachedby = moves + 38;
    nodes[52].reachedby = moves + 18;
    nodes[53].reachedby = moves + 19;
    nodes[54].reachedby = moves + 39;
    nodes[55].reachedby = moves + 20;
    nodes[56].reachedby = moves + 39;
    nodes[57].reachedby = moves + 40;
    nodes[58].reachedby = moves + 3;
    nodes[59].reachedby = moves + 4;
    nodes[60].reachedby = moves + 22;
    nodes[61].reachedby = moves + 28;
    nodes[62].reachedby = moves + 23;
    nodes[63].reachedby = moves + 24;
    nodes[64].reachedby = moves + 29;
    nodes[65].reachedby = moves + 25;
    nodes[66].reachedby = moves + 29;
    nodes[67].reachedby = moves + 30;
    nodes[68].reachedby = moves + 5;
    nodes[69].reachedby = moves + 22;
    nodes[70].reachedby = moves + 33;
    nodes[71].reachedby = moves + 23;
    nodes[72].reachedby = moves + 24;
    nodes[73].reachedby = moves + 34;
    nodes[74].reachedby = moves + 25;
    nodes[75].reachedby = moves + 34;
    nodes[76].reachedby = moves + 35;
    nodes[77].reachedby = moves + 6;
    nodes[78].reachedby = moves + 22;
    nodes[79].reachedby = moves + 38;
    nodes[80].reachedby = moves + 23;
    nodes[81].reachedby = moves + 24;
    nodes[82].reachedby = moves + 39;
    nodes[83].reachedby = moves + 25;
    nodes[84].reachedby = moves + 39;
    nodes[85].reachedby = moves + 40;
    nodes[86].reachedby = moves + 11;
    nodes[87].reachedby = moves + 27;
    nodes[88].reachedby = moves + 29;
    nodes[89].reachedby = moves + 30;
    nodes[90].reachedby = moves + 31;
    nodes[91].reachedby = moves + 7;
    nodes[92].reachedby = moves + 8;
    nodes[93].reachedby = moves + 9;
    nodes[94].reachedby = moves + 30;
    nodes[95].reachedby = moves + 31;
    nodes[96].reachedby = moves + 7;
    nodes[97].reachedby = moves + 8;
    nodes[98].reachedby = moves + 9;
    nodes[99].reachedby = moves + 7;
    nodes[100].reachedby = moves + 8;
    nodes[101].reachedby = moves + 9;
    nodes[102].reachedby = moves + 31;
    nodes[103].reachedby = moves + 11;
    nodes[104].reachedby = moves + 32;
    nodes[105].reachedby = moves + 34;
    nodes[106].reachedby = moves + 35;
    nodes[107].reachedby = moves + 36;
    nodes[108].reachedby = moves + 7;
    nodes[109].reachedby = moves + 8;
    nodes[110].reachedby = moves + 9;
    nodes[111].reachedby = moves + 35;
    nodes[112].reachedby = moves + 36;
    nodes[113].reachedby = moves + 7;
    nodes[114].reachedby = moves + 8;
    nodes[115].reachedby = moves + 9;
    nodes[116].reachedby = moves + 7;
    nodes[117].reachedby = moves + 8;
    nodes[118].reachedby = moves + 9;
    nodes[119].reachedby = moves + 36;
    nodes[120].reachedby = moves + 11;
    nodes[121].reachedby = moves + 37;
    nodes[122].reachedby = moves + 39;
    nodes[123].reachedby = moves + 40;
    nodes[124].reachedby = moves + 41;
    nodes[125].reachedby = moves + 7;
    nodes[126].reachedby = moves + 8;
    nodes[127].reachedby = moves + 9;
    nodes[128].reachedby = moves + 40;
    nodes[129].reachedby = moves + 41;
    nodes[130].reachedby = moves + 7;
    nodes[131].reachedby = moves + 8;
    nodes[132].reachedby = moves + 9;
    nodes[133].reachedby = moves + 7;
    nodes[134].reachedby = moves + 8;
    nodes[135].reachedby = moves + 9;
    nodes[136].reachedby = moves + 41;
    nodes[137].reachedby = moves + 16;
    nodes[138].reachedby = moves + 27;
    nodes[139].reachedby = moves + 29;
    nodes[140].reachedby = moves + 30;
    nodes[141].reachedby = moves + 31;
    nodes[142].reachedby = moves + 7;
    nodes[143].reachedby = moves + 8;
    nodes[144].reachedby = moves + 9;
    nodes[145].reachedby = moves + 30;
    nodes[146].reachedby = moves + 31;
    nodes[147].reachedby = moves + 7;
    nodes[148].reachedby = moves + 8;
    nodes[149].reachedby = moves + 9;
    nodes[150].reachedby = moves + 7;
    nodes[151].reachedby = moves + 8;
    nodes[152].reachedby = moves + 9;
    nodes[153].reachedby = moves + 31;
    nodes[154].reachedby = moves + 16;
    nodes[155].reachedby = moves + 32;
    nodes[156].reachedby = moves + 34;
    nodes[157].reachedby = moves + 35;
    nodes[158].reachedby = moves + 36;
    nodes[159].reachedby = moves + 7;
    nodes[160].reachedby = moves + 8;
    nodes[161].reachedby = moves + 9;
    nodes[162].reachedby = moves + 35;
    nodes[163].reachedby = moves + 36;
    nodes[164].reachedby = moves + 7;
    nodes[165].reachedby = moves + 8;
    nodes[166].reachedby = moves + 9;
    nodes[167].reachedby = moves + 7;
    nodes[168].reachedby = moves + 8;
    nodes[169].reachedby = moves + 9;
    nodes[170].reachedby = moves + 36;
    nodes[171].reachedby = moves + 16;
    nodes[172].reachedby = moves + 37;
    nodes[173].reachedby = moves + 39;
    nodes[174].reachedby = moves + 40;
    nodes[175].reachedby = moves + 41;
    nodes[176].reachedby = moves + 7;
    nodes[177].reachedby = moves + 8;
    nodes[178].reachedby = moves + 9;
    nodes[179].reachedby = moves + 40;
    nodes[180].reachedby = moves + 41;
    nodes[181].reachedby = moves + 7;
    nodes[182].reachedby = moves + 8;
    nodes[183].reachedby = moves + 9;
    nodes[184].reachedby = moves + 7;
    nodes[185].reachedby = moves + 8;
    nodes[186].reachedby = moves + 9;
    nodes[187].reachedby = moves + 41;
    nodes[188].reachedby = moves + 21;
    nodes[189].reachedby = moves + 27;
    nodes[190].reachedby = moves + 29;
    nodes[191].reachedby = moves + 30;
    nodes[192].reachedby = moves + 31;
    nodes[193].reachedby = moves + 7;
    nodes[194].reachedby = moves + 8;
    nodes[195].reachedby = moves + 9;
    nodes[196].reachedby = moves + 30;
    nodes[197].reachedby = moves + 31;
    nodes[198].reachedby = moves + 7;
    nodes[199].reachedby = moves + 8;
    nodes[200].reachedby = moves + 9;
    nodes[201].reachedby = moves + 7;
    nodes[202].reachedby = moves + 8;
    nodes[203].reachedby = moves + 9;
    nodes[204].reachedby = moves + 31;
    nodes[205].reachedby = moves + 21;
    nodes[206].reachedby = moves + 32;
    nodes[207].reachedby = moves + 34;
    nodes[208].reachedby = moves + 35;
    nodes[209].reachedby = moves + 36;
    nodes[210].reachedby = moves + 7;
    nodes[211].reachedby = moves + 8;
    nodes[212].reachedby = moves + 9;
    nodes[213].reachedby = moves + 35;
    nodes[214].reachedby = moves + 36;
    nodes[215].reachedby = moves + 7;
    nodes[216].reachedby = moves + 8;
    nodes[217].reachedby = moves + 9;
    nodes[218].reachedby = moves + 7;
    nodes[219].reachedby = moves + 8;
    nodes[220].reachedby = moves + 9;
    nodes[221].reachedby = moves + 36;
    nodes[222].reachedby = moves + 21;
    nodes[223].reachedby = moves + 37;
    nodes[224].reachedby = moves + 39;
    nodes[225].reachedby = moves + 40;
    nodes[226].reachedby = moves + 41;
    nodes[227].reachedby = moves + 7;
    nodes[228].reachedby = moves + 8;
    nodes[229].reachedby = moves + 9;
    nodes[230].reachedby = moves + 40;
    nodes[231].reachedby = moves + 41;
    nodes[232].reachedby = moves + 7;
    nodes[233].reachedby = moves + 8;
    nodes[234].reachedby = moves + 9;
    nodes[235].reachedby = moves + 7;
    nodes[236].reachedby = moves + 8;
    nodes[237].reachedby = moves + 9;
    nodes[238].reachedby = moves + 41;
    isets[0].player = 0;
    isets[0].move0 = moves + 1;
    isets[0].nmoves = 3;
    isets[1].player = 0;
    isets[1].move0 = moves + 4;
    isets[1].nmoves = 3;
    isets[2].player = 0;
    isets[2].move0 = moves + 7;
    isets[2].nmoves = 3;
    isets[3].player = 1;
    isets[3].move0 = moves + 11;
    isets[3].nmoves = 2;
    isets[4].player = 1;
    isets[4].move0 = moves + 13;
    isets[4].nmoves = 3;
    isets[5].player = 1;
    isets[5].move0 = moves + 16;
    isets[5].nmoves = 2;
    isets[6].player = 1;
    isets[6].move0 = moves + 18;
    isets[6].nmoves = 3;
    isets[7].player = 1;
    isets[7].move0 = moves + 21;
    isets[7].nmoves = 2;
    isets[8].player = 1;
    isets[8].move0 = moves + 23;
    isets[8].nmoves = 3;
    isets[9].player = 2;
    isets[9].move0 = moves + 27;
    isets[9].nmoves = 2;
    isets[10].player = 2;
    isets[10].move0 = moves + 29;
    isets[10].nmoves = 3;
    isets[11].player = 2;
    isets[11].move0 = moves + 32;
    isets[11].nmoves = 2;
    isets[12].player = 2;
    isets[12].move0 = moves + 34;
    isets[12].nmoves = 3;
    isets[13].player = 2;
    isets[13].move0 = moves + 37;
    isets[13].nmoves = 2;
    isets[14].player = 2;
    isets[14].move0 = moves + 39;
    isets[14].nmoves = 3;
    // move 0 is empty sequence for player 0
    moves[1].atiset = isets + 0;
    moves[1].behavprob.num = 1;
    moves[1].behavprob.den = 3;
    moves[2].atiset = isets + 0;
    moves[2].behavprob.num = 1;
    moves[2].behavprob.den = 3;
    moves[3].atiset = isets + 0;
    moves[3].behavprob.num = 1;
    moves[3].behavprob.den = 3;
    moves[4].atiset = isets + 1;
    moves[4].behavprob.num = 1;
    moves[4].behavprob.den = 3;
    moves[5].atiset = isets + 1;
    moves[5].behavprob.num = 1;
    moves[5].behavprob.den = 3;
    moves[6].atiset = isets + 1;
    moves[6].behavprob.num = 1;
    moves[6].behavprob.den = 3;
    moves[7].atiset = isets + 2;
    moves[7].behavprob.num = 1;
    moves[7].behavprob.den = 3;
    moves[8].atiset = isets + 2;
    moves[8].behavprob.num = 1;
    moves[8].behavprob.den = 3;
    moves[9].atiset = isets + 2;
    moves[9].behavprob.num = 1;
    moves[9].behavprob.den = 3;
    // move 10 is empty sequence for player 1
    moves[11].atiset = isets + 3;
    moves[12].atiset = isets + 3;
    moves[13].atiset = isets + 4;
    moves[14].atiset = isets + 4;
    moves[15].atiset = isets + 4;
    moves[16].atiset = isets + 5;
    moves[17].atiset = isets + 5;
    moves[18].atiset = isets + 6;
    moves[19].atiset = isets + 6;
    moves[20].atiset = isets + 6;
    moves[21].atiset = isets + 7;
    moves[22].atiset = isets + 7;
    moves[23].atiset = isets + 8;
    moves[24].atiset = isets + 8;
    moves[25].atiset = isets + 8;
    // move 26 is empty sequence for player 2
    moves[27].atiset = isets + 9;
    moves[28].atiset = isets + 9;
    moves[29].atiset = isets + 10;
    moves[30].atiset = isets + 10;
    moves[31].atiset = isets + 10;
    moves[32].atiset = isets + 11;
    moves[33].atiset = isets + 11;
    moves[34].atiset = isets + 12;
    moves[35].atiset = isets + 12;
    moves[36].atiset = isets + 12;
    moves[37].atiset = isets + 13;
    moves[38].atiset = isets + 13;
    moves[39].atiset = isets + 14;
    moves[40].atiset = isets + 14;
    moves[41].atiset = isets + 14;

}

void tracingexample_orig(void)
{
    int pay[2][8] = { {11, 3, 0,  0, 0, 24, 6, 0},
                      { 3, 0, 0, 10, 4,  0, 0, 1} };
    int i;
    Outcome z;
    alloctree(16, 5, 13, 8);
    firstiset[0] = isets; // player 0 (chance) has 1 information set (so + 1 on next line)
    firstiset[1] = isets + 1; // player 1 has two information sets (so + 3 on next line)
    firstiset[2] = isets + 3; // player 2 is last player and has two information set
    firstmove[0] = moves; // player 0 (chance) has empty sequence plus two moves (so +3 next line)
    firstmove[1] = moves + 3; // player 1 has empty sequence plus four moves (so +8 next line)
    firstmove[2] = moves + 8;
    
    // root node is at index 1 (index 0 is skipped)
    root = nodes + ROOT; // player 1's choice between L and R
    root->father = NULL;
    nodes[2].father = root; // player 1's choice between S and T
    nodes[3].father = nodes + 2; // chance's node
    nodes[4].father = root; // player 2's first choice in L information set
    nodes[5].father = nodes + 3; // player 2's next choice (same information set as above)
    nodes[6].father = nodes + 3; // player 2's first choice in R information set 
    nodes[7].father = nodes + 2; // player 2's second choice in R information set
    // outcomes are in their own nodes
    z = outcomes;
    for (i=8; i<=15; i++)
        {
        nodes[i].father = nodes + i/2;
        nodes[i].terminal = 1;
        nodes[i].outcome  = z;
        z->whichnode = nodes + i;
        z->pay[0] = ratfromi(pay[0][i-8]);
        z->pay[1] = ratfromi(pay[1][i-8]);
        z++;
        }
    nodes[1].iset = firstiset[1]; // i.e., isets + 1 
    nodes[2].iset = firstiset[1]+1;
    nodes[3].iset = firstiset[0]; // chance's information set
    nodes[4].iset = firstiset[2];
    nodes[5].iset = firstiset[2];
    nodes[6].iset = firstiset[2]+1;
    nodes[7].iset = firstiset[2]+1;
    
    nodes[2].reachedby = firstmove[1]+2;    /* note empty sequence  */ // player 1's choice between S + T is reached by player 1's R move
    nodes[3].reachedby = firstmove[1]+3; // chance's node is reached by player 1's choice of S
    nodes[4].reachedby = firstmove[1]+1;
    nodes[5].reachedby = firstmove[0]+1;
    nodes[6].reachedby = firstmove[0]+2;
    nodes[7].reachedby = firstmove[1]+4;
    nodes[8].reachedby  = firstmove[2]+1;
    nodes[9].reachedby  = firstmove[2]+2;
    nodes[10].reachedby = firstmove[2]+1;
    nodes[11].reachedby = firstmove[2]+2;
    nodes[12].reachedby = firstmove[2]+3;
    nodes[13].reachedby = firstmove[2]+4;
    nodes[14].reachedby = firstmove[2]+3;
    nodes[15].reachedby = firstmove[2]+4;
    
    isets[0].player = 0;
    isets[1].player = 1;
    isets[2].player = 1;
    isets[3].player = 2;
    isets[4].player = 2;
    
    isets[0].move0 = firstmove[0]+1;
    isets[1].move0 = firstmove[1]+1;
    isets[2].move0 = firstmove[1]+3;
    isets[3].move0 = firstmove[2]+1;
    isets[4].move0 = firstmove[2]+3;
    
    isets[0].nmoves = 2;
    isets[1].nmoves = 2;
    isets[2].nmoves = 2;
    isets[3].nmoves = 2;
    isets[4].nmoves = 2;
    
    // chance player
    // move 0 is empty sequence
    moves[1].atiset = firstiset[0];
    moves[2].atiset = firstiset[0];
    // player 1
    // move 3 is empty sequence
    moves[4].atiset = firstiset[1];
    moves[5].atiset = firstiset[1];
    moves[6].atiset = firstiset[1]+1;
    moves[7].atiset = firstiset[1]+1;
    // player 2
    // move 4 is empty sequence
    moves[9].atiset  = firstiset[2];
    moves[10].atiset = firstiset[2];
    moves[11].atiset = firstiset[2]+1;
    moves[12].atiset = firstiset[2]+1;
    
    // probabilities for chance (at chance's sole information set), expressed with numerator and denominator
    moves[1].behavprob.num = 1;
    moves[1].behavprob.den = 2;
    moves[2].behavprob.num = 1;
    moves[2].behavprob.den = 2;

    rawtreeprint(); // DEBUG
}       /* end of  tracingexample()     */

