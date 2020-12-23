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
    int pay[2][252] = {
    { 1013333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1013333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1013333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1013333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1013333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1013333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1013333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1013333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1013333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000, 1023333, 1040000, 982500, 1082500, 1056667, 1097500, 1000000 },
    { 946667, 940000, 982500, 882500, 923333, 900000, 1000000, 946667, 940000, 982500, 882500, 923333, 900000, 1000000, 946667, 940000, 982500, 882500, 923333, 900000, 1000000, 946667, 940000, 982500, 882500, 923333, 900000, 1000000, 946667, 940000, 982500, 882500, 923333, 900000, 1000000, 946667, 940000, 982500, 882500, 923333, 900000, 1000000, 946667, 940000, 982500, 882500, 923333, 900000, 1000000, 946667, 940000, 982500, 882500, 923333, 900000, 1000000, 946667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000, 956667, 940000, 982500, 882500, 923333, 900000, 1000000 }
    };
    alloctree(560, 23, 51, 252);
    Outcome z = outcomes;
    firstiset[0] = isets + 0;
    firstiset[1] = isets + 11;
    firstiset[2] = isets + 17;
    firstmove[0] = moves + 0;
    firstmove[1] = moves + 25;
    firstmove[2] = moves + 38;

    // root node is at index 1 (index 0 is skipped)
    root = nodes + ROOT;
    root->father = NULL;
    nodes[2].father = nodes + 1;

    nodes[3].father = nodes + 2;

    nodes[4].father = nodes + 3;

    nodes[5].father = nodes + 4;

    nodes[6].father = nodes + 5;

    nodes[7].father = nodes + 6;

    nodes[8].father = nodes + 7;

    nodes[9].father = nodes + 8;

    nodes[10].father = nodes + 8;

    nodes[11].father = nodes + 10;

    nodes[12].father = nodes + 11;

    nodes[13].father = nodes + 4;

    nodes[14].father = nodes + 13;

    nodes[15].father = nodes + 14;

    nodes[16].father = nodes + 15;

    nodes[17].father = nodes + 16;

    nodes[18].father = nodes + 16;

    nodes[19].father = nodes + 18;

    nodes[20].father = nodes + 19;

    nodes[21].father = nodes + 4;

    nodes[22].father = nodes + 21;

    nodes[23].father = nodes + 22;

    nodes[24].father = nodes + 23;

    nodes[25].father = nodes + 24;

    nodes[26].father = nodes + 24;

    nodes[27].father = nodes + 26;

    nodes[28].father = nodes + 27;

    nodes[29].father = nodes + 3;

    nodes[30].father = nodes + 29;

    nodes[31].father = nodes + 30;

    nodes[32].father = nodes + 31;

    nodes[33].father = nodes + 32;

    nodes[34].father = nodes + 33;

    nodes[35].father = nodes + 33;

    nodes[36].father = nodes + 35;

    nodes[37].father = nodes + 36;

    nodes[38].father = nodes + 29;

    nodes[39].father = nodes + 38;

    nodes[40].father = nodes + 39;

    nodes[41].father = nodes + 40;

    nodes[42].father = nodes + 41;

    nodes[43].father = nodes + 41;

    nodes[44].father = nodes + 43;

    nodes[45].father = nodes + 44;

    nodes[46].father = nodes + 29;

    nodes[47].father = nodes + 46;

    nodes[48].father = nodes + 47;

    nodes[49].father = nodes + 48;

    nodes[50].father = nodes + 49;

    nodes[51].father = nodes + 49;

    nodes[52].father = nodes + 51;

    nodes[53].father = nodes + 52;

    nodes[54].father = nodes + 3;

    nodes[55].father = nodes + 54;

    nodes[56].father = nodes + 55;

    nodes[57].father = nodes + 56;

    nodes[58].father = nodes + 57;

    nodes[59].father = nodes + 58;

    nodes[60].father = nodes + 58;

    nodes[61].father = nodes + 60;

    nodes[62].father = nodes + 61;

    nodes[63].father = nodes + 54;

    nodes[64].father = nodes + 63;

    nodes[65].father = nodes + 64;

    nodes[66].father = nodes + 65;

    nodes[67].father = nodes + 66;

    nodes[68].father = nodes + 66;

    nodes[69].father = nodes + 68;

    nodes[70].father = nodes + 69;

    nodes[71].father = nodes + 54;

    nodes[72].father = nodes + 71;

    nodes[73].father = nodes + 72;

    nodes[74].father = nodes + 73;

    nodes[75].father = nodes + 74;

    nodes[76].father = nodes + 74;

    nodes[77].father = nodes + 76;

    nodes[78].father = nodes + 77;

    nodes[79].father = nodes + 2;

    nodes[80].father = nodes + 79;

    nodes[81].father = nodes + 80;

    nodes[82].father = nodes + 81;

    nodes[83].father = nodes + 82;

    nodes[84].father = nodes + 83;

    nodes[85].father = nodes + 84;

    nodes[86].father = nodes + 84;

    nodes[87].father = nodes + 86;

    nodes[88].father = nodes + 87;

    nodes[89].father = nodes + 80;

    nodes[90].father = nodes + 89;

    nodes[91].father = nodes + 90;

    nodes[92].father = nodes + 91;

    nodes[93].father = nodes + 92;

    nodes[94].father = nodes + 92;

    nodes[95].father = nodes + 94;

    nodes[96].father = nodes + 95;

    nodes[97].father = nodes + 80;

    nodes[98].father = nodes + 97;

    nodes[99].father = nodes + 98;

    nodes[100].father = nodes + 99;

    nodes[101].father = nodes + 100;

    nodes[102].father = nodes + 100;

    nodes[103].father = nodes + 102;

    nodes[104].father = nodes + 103;

    nodes[105].father = nodes + 79;

    nodes[106].father = nodes + 105;

    nodes[107].father = nodes + 106;

    nodes[108].father = nodes + 107;

    nodes[109].father = nodes + 108;

    nodes[110].father = nodes + 109;

    nodes[111].father = nodes + 109;

    nodes[112].father = nodes + 111;

    nodes[113].father = nodes + 112;

    nodes[114].father = nodes + 105;

    nodes[115].father = nodes + 114;

    nodes[116].father = nodes + 115;

    nodes[117].father = nodes + 116;

    nodes[118].father = nodes + 117;

    nodes[119].father = nodes + 117;

    nodes[120].father = nodes + 119;

    nodes[121].father = nodes + 120;

    nodes[122].father = nodes + 105;

    nodes[123].father = nodes + 122;

    nodes[124].father = nodes + 123;

    nodes[125].father = nodes + 124;

    nodes[126].father = nodes + 125;

    nodes[127].father = nodes + 125;

    nodes[128].father = nodes + 127;

    nodes[129].father = nodes + 128;

    nodes[130].father = nodes + 79;

    nodes[131].father = nodes + 130;

    nodes[132].father = nodes + 131;

    nodes[133].father = nodes + 132;

    nodes[134].father = nodes + 133;

    nodes[135].father = nodes + 134;

    nodes[136].father = nodes + 134;

    nodes[137].father = nodes + 136;

    nodes[138].father = nodes + 137;

    nodes[139].father = nodes + 130;

    nodes[140].father = nodes + 139;

    nodes[141].father = nodes + 140;

    nodes[142].father = nodes + 141;

    nodes[143].father = nodes + 142;

    nodes[144].father = nodes + 142;

    nodes[145].father = nodes + 144;

    nodes[146].father = nodes + 145;

    nodes[147].father = nodes + 130;

    nodes[148].father = nodes + 147;

    nodes[149].father = nodes + 148;

    nodes[150].father = nodes + 149;

    nodes[151].father = nodes + 150;

    nodes[152].father = nodes + 150;

    nodes[153].father = nodes + 152;

    nodes[154].father = nodes + 153;

    nodes[155].father = nodes + 1;

    nodes[156].father = nodes + 155;

    nodes[157].father = nodes + 156;

    nodes[158].father = nodes + 157;

    nodes[159].father = nodes + 158;

    nodes[160].father = nodes + 159;

    nodes[161].father = nodes + 160;

    nodes[162].father = nodes + 161;

    nodes[163].father = nodes + 161;

    nodes[164].father = nodes + 163;

    nodes[165].father = nodes + 164;

    nodes[166].father = nodes + 157;

    nodes[167].father = nodes + 166;

    nodes[168].father = nodes + 167;

    nodes[169].father = nodes + 168;

    nodes[170].father = nodes + 169;

    nodes[171].father = nodes + 169;

    nodes[172].father = nodes + 171;

    nodes[173].father = nodes + 172;

    nodes[174].father = nodes + 157;

    nodes[175].father = nodes + 174;

    nodes[176].father = nodes + 175;

    nodes[177].father = nodes + 176;

    nodes[178].father = nodes + 177;

    nodes[179].father = nodes + 177;

    nodes[180].father = nodes + 179;

    nodes[181].father = nodes + 180;

    nodes[182].father = nodes + 156;

    nodes[183].father = nodes + 182;

    nodes[184].father = nodes + 183;

    nodes[185].father = nodes + 184;

    nodes[186].father = nodes + 185;

    nodes[187].father = nodes + 186;

    nodes[188].father = nodes + 186;

    nodes[189].father = nodes + 188;

    nodes[190].father = nodes + 189;

    nodes[191].father = nodes + 182;

    nodes[192].father = nodes + 191;

    nodes[193].father = nodes + 192;

    nodes[194].father = nodes + 193;

    nodes[195].father = nodes + 194;

    nodes[196].father = nodes + 194;

    nodes[197].father = nodes + 196;

    nodes[198].father = nodes + 197;

    nodes[199].father = nodes + 182;

    nodes[200].father = nodes + 199;

    nodes[201].father = nodes + 200;

    nodes[202].father = nodes + 201;

    nodes[203].father = nodes + 202;

    nodes[204].father = nodes + 202;

    nodes[205].father = nodes + 204;

    nodes[206].father = nodes + 205;

    nodes[207].father = nodes + 156;

    nodes[208].father = nodes + 207;

    nodes[209].father = nodes + 208;

    nodes[210].father = nodes + 209;

    nodes[211].father = nodes + 210;

    nodes[212].father = nodes + 211;

    nodes[213].father = nodes + 211;

    nodes[214].father = nodes + 213;

    nodes[215].father = nodes + 214;

    nodes[216].father = nodes + 207;

    nodes[217].father = nodes + 216;

    nodes[218].father = nodes + 217;

    nodes[219].father = nodes + 218;

    nodes[220].father = nodes + 219;

    nodes[221].father = nodes + 219;

    nodes[222].father = nodes + 221;

    nodes[223].father = nodes + 222;

    nodes[224].father = nodes + 207;

    nodes[225].father = nodes + 224;

    nodes[226].father = nodes + 225;

    nodes[227].father = nodes + 226;

    nodes[228].father = nodes + 227;

    nodes[229].father = nodes + 227;

    nodes[230].father = nodes + 229;

    nodes[231].father = nodes + 230;

    nodes[232].father = nodes + 155;

    nodes[233].father = nodes + 232;

    nodes[234].father = nodes + 233;

    nodes[235].father = nodes + 234;

    nodes[236].father = nodes + 235;

    nodes[237].father = nodes + 236;

    nodes[238].father = nodes + 237;

    nodes[239].father = nodes + 237;

    nodes[240].father = nodes + 239;

    nodes[241].father = nodes + 240;

    nodes[242].father = nodes + 233;

    nodes[243].father = nodes + 242;

    nodes[244].father = nodes + 243;

    nodes[245].father = nodes + 244;

    nodes[246].father = nodes + 245;

    nodes[247].father = nodes + 245;

    nodes[248].father = nodes + 247;

    nodes[249].father = nodes + 248;

    nodes[250].father = nodes + 233;

    nodes[251].father = nodes + 250;

    nodes[252].father = nodes + 251;

    nodes[253].father = nodes + 252;

    nodes[254].father = nodes + 253;

    nodes[255].father = nodes + 253;

    nodes[256].father = nodes + 255;

    nodes[257].father = nodes + 256;

    nodes[258].father = nodes + 232;

    nodes[259].father = nodes + 258;

    nodes[260].father = nodes + 259;

    nodes[261].father = nodes + 260;

    nodes[262].father = nodes + 261;

    nodes[263].father = nodes + 262;

    nodes[264].father = nodes + 262;

    nodes[265].father = nodes + 264;

    nodes[266].father = nodes + 265;

    nodes[267].father = nodes + 258;

    nodes[268].father = nodes + 267;

    nodes[269].father = nodes + 268;

    nodes[270].father = nodes + 269;

    nodes[271].father = nodes + 270;

    nodes[272].father = nodes + 270;

    nodes[273].father = nodes + 272;

    nodes[274].father = nodes + 273;

    nodes[275].father = nodes + 258;

    nodes[276].father = nodes + 275;

    nodes[277].father = nodes + 276;

    nodes[278].father = nodes + 277;

    nodes[279].father = nodes + 278;

    nodes[280].father = nodes + 278;

    nodes[281].father = nodes + 280;

    nodes[282].father = nodes + 281;

    nodes[283].father = nodes + 232;

    nodes[284].father = nodes + 283;

    nodes[285].father = nodes + 284;

    nodes[286].father = nodes + 285;

    nodes[287].father = nodes + 286;

    nodes[288].father = nodes + 287;

    nodes[289].father = nodes + 287;

    nodes[290].father = nodes + 289;

    nodes[291].father = nodes + 290;

    nodes[292].father = nodes + 283;

    nodes[293].father = nodes + 292;

    nodes[294].father = nodes + 293;

    nodes[295].father = nodes + 294;

    nodes[296].father = nodes + 295;

    nodes[297].father = nodes + 295;

    nodes[298].father = nodes + 297;

    nodes[299].father = nodes + 298;

    nodes[300].father = nodes + 283;

    nodes[301].father = nodes + 300;

    nodes[302].father = nodes + 301;

    nodes[303].father = nodes + 302;

    nodes[304].father = nodes + 303;

    nodes[305].father = nodes + 303;

    nodes[306].father = nodes + 305;

    nodes[307].father = nodes + 306;

    nodes[308].father = nodes + 9;

    nodes[308].terminal = 1;
    nodes[308].outcome = z;
    z->whichnode = nodes + 308;
    z->pay[0] = ratfromi(pay[0][0]);
    z->pay[1] = ratfromi(pay[1][0]);
    z++;
    nodes[309].father = nodes + 9;

    nodes[309].terminal = 1;
    nodes[309].outcome = z;
    z->whichnode = nodes + 309;
    z->pay[0] = ratfromi(pay[0][1]);
    z->pay[1] = ratfromi(pay[1][1]);
    z++;
    nodes[310].father = nodes + 12;

    nodes[310].terminal = 1;
    nodes[310].outcome = z;
    z->whichnode = nodes + 310;
    z->pay[0] = ratfromi(pay[0][2]);
    z->pay[1] = ratfromi(pay[1][2]);
    z++;
    nodes[311].father = nodes + 12;

    nodes[311].terminal = 1;
    nodes[311].outcome = z;
    z->whichnode = nodes + 311;
    z->pay[0] = ratfromi(pay[0][3]);
    z->pay[1] = ratfromi(pay[1][3]);
    z++;
    nodes[312].father = nodes + 10;

    nodes[312].terminal = 1;
    nodes[312].outcome = z;
    z->whichnode = nodes + 312;
    z->pay[0] = ratfromi(pay[0][4]);
    z->pay[1] = ratfromi(pay[1][4]);
    z++;
    nodes[313].father = nodes + 6;

    nodes[313].terminal = 1;
    nodes[313].outcome = z;
    z->whichnode = nodes + 313;
    z->pay[0] = ratfromi(pay[0][5]);
    z->pay[1] = ratfromi(pay[1][5]);
    z++;
    nodes[314].father = nodes + 5;

    nodes[314].terminal = 1;
    nodes[314].outcome = z;
    z->whichnode = nodes + 314;
    z->pay[0] = ratfromi(pay[0][6]);
    z->pay[1] = ratfromi(pay[1][6]);
    z++;
    nodes[315].father = nodes + 17;

    nodes[315].terminal = 1;
    nodes[315].outcome = z;
    z->whichnode = nodes + 315;
    z->pay[0] = ratfromi(pay[0][7]);
    z->pay[1] = ratfromi(pay[1][7]);
    z++;
    nodes[316].father = nodes + 17;

    nodes[316].terminal = 1;
    nodes[316].outcome = z;
    z->whichnode = nodes + 316;
    z->pay[0] = ratfromi(pay[0][8]);
    z->pay[1] = ratfromi(pay[1][8]);
    z++;
    nodes[317].father = nodes + 20;

    nodes[317].terminal = 1;
    nodes[317].outcome = z;
    z->whichnode = nodes + 317;
    z->pay[0] = ratfromi(pay[0][9]);
    z->pay[1] = ratfromi(pay[1][9]);
    z++;
    nodes[318].father = nodes + 20;

    nodes[318].terminal = 1;
    nodes[318].outcome = z;
    z->whichnode = nodes + 318;
    z->pay[0] = ratfromi(pay[0][10]);
    z->pay[1] = ratfromi(pay[1][10]);
    z++;
    nodes[319].father = nodes + 18;

    nodes[319].terminal = 1;
    nodes[319].outcome = z;
    z->whichnode = nodes + 319;
    z->pay[0] = ratfromi(pay[0][11]);
    z->pay[1] = ratfromi(pay[1][11]);
    z++;
    nodes[320].father = nodes + 14;

    nodes[320].terminal = 1;
    nodes[320].outcome = z;
    z->whichnode = nodes + 320;
    z->pay[0] = ratfromi(pay[0][12]);
    z->pay[1] = ratfromi(pay[1][12]);
    z++;
    nodes[321].father = nodes + 13;

    nodes[321].terminal = 1;
    nodes[321].outcome = z;
    z->whichnode = nodes + 321;
    z->pay[0] = ratfromi(pay[0][13]);
    z->pay[1] = ratfromi(pay[1][13]);
    z++;
    nodes[322].father = nodes + 25;

    nodes[322].terminal = 1;
    nodes[322].outcome = z;
    z->whichnode = nodes + 322;
    z->pay[0] = ratfromi(pay[0][14]);
    z->pay[1] = ratfromi(pay[1][14]);
    z++;
    nodes[323].father = nodes + 25;

    nodes[323].terminal = 1;
    nodes[323].outcome = z;
    z->whichnode = nodes + 323;
    z->pay[0] = ratfromi(pay[0][15]);
    z->pay[1] = ratfromi(pay[1][15]);
    z++;
    nodes[324].father = nodes + 28;

    nodes[324].terminal = 1;
    nodes[324].outcome = z;
    z->whichnode = nodes + 324;
    z->pay[0] = ratfromi(pay[0][16]);
    z->pay[1] = ratfromi(pay[1][16]);
    z++;
    nodes[325].father = nodes + 28;

    nodes[325].terminal = 1;
    nodes[325].outcome = z;
    z->whichnode = nodes + 325;
    z->pay[0] = ratfromi(pay[0][17]);
    z->pay[1] = ratfromi(pay[1][17]);
    z++;
    nodes[326].father = nodes + 26;

    nodes[326].terminal = 1;
    nodes[326].outcome = z;
    z->whichnode = nodes + 326;
    z->pay[0] = ratfromi(pay[0][18]);
    z->pay[1] = ratfromi(pay[1][18]);
    z++;
    nodes[327].father = nodes + 22;

    nodes[327].terminal = 1;
    nodes[327].outcome = z;
    z->whichnode = nodes + 327;
    z->pay[0] = ratfromi(pay[0][19]);
    z->pay[1] = ratfromi(pay[1][19]);
    z++;
    nodes[328].father = nodes + 21;

    nodes[328].terminal = 1;
    nodes[328].outcome = z;
    z->whichnode = nodes + 328;
    z->pay[0] = ratfromi(pay[0][20]);
    z->pay[1] = ratfromi(pay[1][20]);
    z++;
    nodes[329].father = nodes + 34;

    nodes[329].terminal = 1;
    nodes[329].outcome = z;
    z->whichnode = nodes + 329;
    z->pay[0] = ratfromi(pay[0][21]);
    z->pay[1] = ratfromi(pay[1][21]);
    z++;
    nodes[330].father = nodes + 34;

    nodes[330].terminal = 1;
    nodes[330].outcome = z;
    z->whichnode = nodes + 330;
    z->pay[0] = ratfromi(pay[0][22]);
    z->pay[1] = ratfromi(pay[1][22]);
    z++;
    nodes[331].father = nodes + 37;

    nodes[331].terminal = 1;
    nodes[331].outcome = z;
    z->whichnode = nodes + 331;
    z->pay[0] = ratfromi(pay[0][23]);
    z->pay[1] = ratfromi(pay[1][23]);
    z++;
    nodes[332].father = nodes + 37;

    nodes[332].terminal = 1;
    nodes[332].outcome = z;
    z->whichnode = nodes + 332;
    z->pay[0] = ratfromi(pay[0][24]);
    z->pay[1] = ratfromi(pay[1][24]);
    z++;
    nodes[333].father = nodes + 35;

    nodes[333].terminal = 1;
    nodes[333].outcome = z;
    z->whichnode = nodes + 333;
    z->pay[0] = ratfromi(pay[0][25]);
    z->pay[1] = ratfromi(pay[1][25]);
    z++;
    nodes[334].father = nodes + 31;

    nodes[334].terminal = 1;
    nodes[334].outcome = z;
    z->whichnode = nodes + 334;
    z->pay[0] = ratfromi(pay[0][26]);
    z->pay[1] = ratfromi(pay[1][26]);
    z++;
    nodes[335].father = nodes + 30;

    nodes[335].terminal = 1;
    nodes[335].outcome = z;
    z->whichnode = nodes + 335;
    z->pay[0] = ratfromi(pay[0][27]);
    z->pay[1] = ratfromi(pay[1][27]);
    z++;
    nodes[336].father = nodes + 42;

    nodes[336].terminal = 1;
    nodes[336].outcome = z;
    z->whichnode = nodes + 336;
    z->pay[0] = ratfromi(pay[0][28]);
    z->pay[1] = ratfromi(pay[1][28]);
    z++;
    nodes[337].father = nodes + 42;

    nodes[337].terminal = 1;
    nodes[337].outcome = z;
    z->whichnode = nodes + 337;
    z->pay[0] = ratfromi(pay[0][29]);
    z->pay[1] = ratfromi(pay[1][29]);
    z++;
    nodes[338].father = nodes + 45;

    nodes[338].terminal = 1;
    nodes[338].outcome = z;
    z->whichnode = nodes + 338;
    z->pay[0] = ratfromi(pay[0][30]);
    z->pay[1] = ratfromi(pay[1][30]);
    z++;
    nodes[339].father = nodes + 45;

    nodes[339].terminal = 1;
    nodes[339].outcome = z;
    z->whichnode = nodes + 339;
    z->pay[0] = ratfromi(pay[0][31]);
    z->pay[1] = ratfromi(pay[1][31]);
    z++;
    nodes[340].father = nodes + 43;

    nodes[340].terminal = 1;
    nodes[340].outcome = z;
    z->whichnode = nodes + 340;
    z->pay[0] = ratfromi(pay[0][32]);
    z->pay[1] = ratfromi(pay[1][32]);
    z++;
    nodes[341].father = nodes + 39;

    nodes[341].terminal = 1;
    nodes[341].outcome = z;
    z->whichnode = nodes + 341;
    z->pay[0] = ratfromi(pay[0][33]);
    z->pay[1] = ratfromi(pay[1][33]);
    z++;
    nodes[342].father = nodes + 38;

    nodes[342].terminal = 1;
    nodes[342].outcome = z;
    z->whichnode = nodes + 342;
    z->pay[0] = ratfromi(pay[0][34]);
    z->pay[1] = ratfromi(pay[1][34]);
    z++;
    nodes[343].father = nodes + 50;

    nodes[343].terminal = 1;
    nodes[343].outcome = z;
    z->whichnode = nodes + 343;
    z->pay[0] = ratfromi(pay[0][35]);
    z->pay[1] = ratfromi(pay[1][35]);
    z++;
    nodes[344].father = nodes + 50;

    nodes[344].terminal = 1;
    nodes[344].outcome = z;
    z->whichnode = nodes + 344;
    z->pay[0] = ratfromi(pay[0][36]);
    z->pay[1] = ratfromi(pay[1][36]);
    z++;
    nodes[345].father = nodes + 53;

    nodes[345].terminal = 1;
    nodes[345].outcome = z;
    z->whichnode = nodes + 345;
    z->pay[0] = ratfromi(pay[0][37]);
    z->pay[1] = ratfromi(pay[1][37]);
    z++;
    nodes[346].father = nodes + 53;

    nodes[346].terminal = 1;
    nodes[346].outcome = z;
    z->whichnode = nodes + 346;
    z->pay[0] = ratfromi(pay[0][38]);
    z->pay[1] = ratfromi(pay[1][38]);
    z++;
    nodes[347].father = nodes + 51;

    nodes[347].terminal = 1;
    nodes[347].outcome = z;
    z->whichnode = nodes + 347;
    z->pay[0] = ratfromi(pay[0][39]);
    z->pay[1] = ratfromi(pay[1][39]);
    z++;
    nodes[348].father = nodes + 47;

    nodes[348].terminal = 1;
    nodes[348].outcome = z;
    z->whichnode = nodes + 348;
    z->pay[0] = ratfromi(pay[0][40]);
    z->pay[1] = ratfromi(pay[1][40]);
    z++;
    nodes[349].father = nodes + 46;

    nodes[349].terminal = 1;
    nodes[349].outcome = z;
    z->whichnode = nodes + 349;
    z->pay[0] = ratfromi(pay[0][41]);
    z->pay[1] = ratfromi(pay[1][41]);
    z++;
    nodes[350].father = nodes + 59;

    nodes[350].terminal = 1;
    nodes[350].outcome = z;
    z->whichnode = nodes + 350;
    z->pay[0] = ratfromi(pay[0][42]);
    z->pay[1] = ratfromi(pay[1][42]);
    z++;
    nodes[351].father = nodes + 59;

    nodes[351].terminal = 1;
    nodes[351].outcome = z;
    z->whichnode = nodes + 351;
    z->pay[0] = ratfromi(pay[0][43]);
    z->pay[1] = ratfromi(pay[1][43]);
    z++;
    nodes[352].father = nodes + 62;

    nodes[352].terminal = 1;
    nodes[352].outcome = z;
    z->whichnode = nodes + 352;
    z->pay[0] = ratfromi(pay[0][44]);
    z->pay[1] = ratfromi(pay[1][44]);
    z++;
    nodes[353].father = nodes + 62;

    nodes[353].terminal = 1;
    nodes[353].outcome = z;
    z->whichnode = nodes + 353;
    z->pay[0] = ratfromi(pay[0][45]);
    z->pay[1] = ratfromi(pay[1][45]);
    z++;
    nodes[354].father = nodes + 60;

    nodes[354].terminal = 1;
    nodes[354].outcome = z;
    z->whichnode = nodes + 354;
    z->pay[0] = ratfromi(pay[0][46]);
    z->pay[1] = ratfromi(pay[1][46]);
    z++;
    nodes[355].father = nodes + 56;

    nodes[355].terminal = 1;
    nodes[355].outcome = z;
    z->whichnode = nodes + 355;
    z->pay[0] = ratfromi(pay[0][47]);
    z->pay[1] = ratfromi(pay[1][47]);
    z++;
    nodes[356].father = nodes + 55;

    nodes[356].terminal = 1;
    nodes[356].outcome = z;
    z->whichnode = nodes + 356;
    z->pay[0] = ratfromi(pay[0][48]);
    z->pay[1] = ratfromi(pay[1][48]);
    z++;
    nodes[357].father = nodes + 67;

    nodes[357].terminal = 1;
    nodes[357].outcome = z;
    z->whichnode = nodes + 357;
    z->pay[0] = ratfromi(pay[0][49]);
    z->pay[1] = ratfromi(pay[1][49]);
    z++;
    nodes[358].father = nodes + 67;

    nodes[358].terminal = 1;
    nodes[358].outcome = z;
    z->whichnode = nodes + 358;
    z->pay[0] = ratfromi(pay[0][50]);
    z->pay[1] = ratfromi(pay[1][50]);
    z++;
    nodes[359].father = nodes + 70;

    nodes[359].terminal = 1;
    nodes[359].outcome = z;
    z->whichnode = nodes + 359;
    z->pay[0] = ratfromi(pay[0][51]);
    z->pay[1] = ratfromi(pay[1][51]);
    z++;
    nodes[360].father = nodes + 70;

    nodes[360].terminal = 1;
    nodes[360].outcome = z;
    z->whichnode = nodes + 360;
    z->pay[0] = ratfromi(pay[0][52]);
    z->pay[1] = ratfromi(pay[1][52]);
    z++;
    nodes[361].father = nodes + 68;

    nodes[361].terminal = 1;
    nodes[361].outcome = z;
    z->whichnode = nodes + 361;
    z->pay[0] = ratfromi(pay[0][53]);
    z->pay[1] = ratfromi(pay[1][53]);
    z++;
    nodes[362].father = nodes + 64;

    nodes[362].terminal = 1;
    nodes[362].outcome = z;
    z->whichnode = nodes + 362;
    z->pay[0] = ratfromi(pay[0][54]);
    z->pay[1] = ratfromi(pay[1][54]);
    z++;
    nodes[363].father = nodes + 63;

    nodes[363].terminal = 1;
    nodes[363].outcome = z;
    z->whichnode = nodes + 363;
    z->pay[0] = ratfromi(pay[0][55]);
    z->pay[1] = ratfromi(pay[1][55]);
    z++;
    nodes[364].father = nodes + 75;

    nodes[364].terminal = 1;
    nodes[364].outcome = z;
    z->whichnode = nodes + 364;
    z->pay[0] = ratfromi(pay[0][56]);
    z->pay[1] = ratfromi(pay[1][56]);
    z++;
    nodes[365].father = nodes + 75;

    nodes[365].terminal = 1;
    nodes[365].outcome = z;
    z->whichnode = nodes + 365;
    z->pay[0] = ratfromi(pay[0][57]);
    z->pay[1] = ratfromi(pay[1][57]);
    z++;
    nodes[366].father = nodes + 78;

    nodes[366].terminal = 1;
    nodes[366].outcome = z;
    z->whichnode = nodes + 366;
    z->pay[0] = ratfromi(pay[0][58]);
    z->pay[1] = ratfromi(pay[1][58]);
    z++;
    nodes[367].father = nodes + 78;

    nodes[367].terminal = 1;
    nodes[367].outcome = z;
    z->whichnode = nodes + 367;
    z->pay[0] = ratfromi(pay[0][59]);
    z->pay[1] = ratfromi(pay[1][59]);
    z++;
    nodes[368].father = nodes + 76;

    nodes[368].terminal = 1;
    nodes[368].outcome = z;
    z->whichnode = nodes + 368;
    z->pay[0] = ratfromi(pay[0][60]);
    z->pay[1] = ratfromi(pay[1][60]);
    z++;
    nodes[369].father = nodes + 72;

    nodes[369].terminal = 1;
    nodes[369].outcome = z;
    z->whichnode = nodes + 369;
    z->pay[0] = ratfromi(pay[0][61]);
    z->pay[1] = ratfromi(pay[1][61]);
    z++;
    nodes[370].father = nodes + 71;

    nodes[370].terminal = 1;
    nodes[370].outcome = z;
    z->whichnode = nodes + 370;
    z->pay[0] = ratfromi(pay[0][62]);
    z->pay[1] = ratfromi(pay[1][62]);
    z++;
    nodes[371].father = nodes + 85;

    nodes[371].terminal = 1;
    nodes[371].outcome = z;
    z->whichnode = nodes + 371;
    z->pay[0] = ratfromi(pay[0][63]);
    z->pay[1] = ratfromi(pay[1][63]);
    z++;
    nodes[372].father = nodes + 85;

    nodes[372].terminal = 1;
    nodes[372].outcome = z;
    z->whichnode = nodes + 372;
    z->pay[0] = ratfromi(pay[0][64]);
    z->pay[1] = ratfromi(pay[1][64]);
    z++;
    nodes[373].father = nodes + 88;

    nodes[373].terminal = 1;
    nodes[373].outcome = z;
    z->whichnode = nodes + 373;
    z->pay[0] = ratfromi(pay[0][65]);
    z->pay[1] = ratfromi(pay[1][65]);
    z++;
    nodes[374].father = nodes + 88;

    nodes[374].terminal = 1;
    nodes[374].outcome = z;
    z->whichnode = nodes + 374;
    z->pay[0] = ratfromi(pay[0][66]);
    z->pay[1] = ratfromi(pay[1][66]);
    z++;
    nodes[375].father = nodes + 86;

    nodes[375].terminal = 1;
    nodes[375].outcome = z;
    z->whichnode = nodes + 375;
    z->pay[0] = ratfromi(pay[0][67]);
    z->pay[1] = ratfromi(pay[1][67]);
    z++;
    nodes[376].father = nodes + 82;

    nodes[376].terminal = 1;
    nodes[376].outcome = z;
    z->whichnode = nodes + 376;
    z->pay[0] = ratfromi(pay[0][68]);
    z->pay[1] = ratfromi(pay[1][68]);
    z++;
    nodes[377].father = nodes + 81;

    nodes[377].terminal = 1;
    nodes[377].outcome = z;
    z->whichnode = nodes + 377;
    z->pay[0] = ratfromi(pay[0][69]);
    z->pay[1] = ratfromi(pay[1][69]);
    z++;
    nodes[378].father = nodes + 93;

    nodes[378].terminal = 1;
    nodes[378].outcome = z;
    z->whichnode = nodes + 378;
    z->pay[0] = ratfromi(pay[0][70]);
    z->pay[1] = ratfromi(pay[1][70]);
    z++;
    nodes[379].father = nodes + 93;

    nodes[379].terminal = 1;
    nodes[379].outcome = z;
    z->whichnode = nodes + 379;
    z->pay[0] = ratfromi(pay[0][71]);
    z->pay[1] = ratfromi(pay[1][71]);
    z++;
    nodes[380].father = nodes + 96;

    nodes[380].terminal = 1;
    nodes[380].outcome = z;
    z->whichnode = nodes + 380;
    z->pay[0] = ratfromi(pay[0][72]);
    z->pay[1] = ratfromi(pay[1][72]);
    z++;
    nodes[381].father = nodes + 96;

    nodes[381].terminal = 1;
    nodes[381].outcome = z;
    z->whichnode = nodes + 381;
    z->pay[0] = ratfromi(pay[0][73]);
    z->pay[1] = ratfromi(pay[1][73]);
    z++;
    nodes[382].father = nodes + 94;

    nodes[382].terminal = 1;
    nodes[382].outcome = z;
    z->whichnode = nodes + 382;
    z->pay[0] = ratfromi(pay[0][74]);
    z->pay[1] = ratfromi(pay[1][74]);
    z++;
    nodes[383].father = nodes + 90;

    nodes[383].terminal = 1;
    nodes[383].outcome = z;
    z->whichnode = nodes + 383;
    z->pay[0] = ratfromi(pay[0][75]);
    z->pay[1] = ratfromi(pay[1][75]);
    z++;
    nodes[384].father = nodes + 89;

    nodes[384].terminal = 1;
    nodes[384].outcome = z;
    z->whichnode = nodes + 384;
    z->pay[0] = ratfromi(pay[0][76]);
    z->pay[1] = ratfromi(pay[1][76]);
    z++;
    nodes[385].father = nodes + 101;

    nodes[385].terminal = 1;
    nodes[385].outcome = z;
    z->whichnode = nodes + 385;
    z->pay[0] = ratfromi(pay[0][77]);
    z->pay[1] = ratfromi(pay[1][77]);
    z++;
    nodes[386].father = nodes + 101;

    nodes[386].terminal = 1;
    nodes[386].outcome = z;
    z->whichnode = nodes + 386;
    z->pay[0] = ratfromi(pay[0][78]);
    z->pay[1] = ratfromi(pay[1][78]);
    z++;
    nodes[387].father = nodes + 104;

    nodes[387].terminal = 1;
    nodes[387].outcome = z;
    z->whichnode = nodes + 387;
    z->pay[0] = ratfromi(pay[0][79]);
    z->pay[1] = ratfromi(pay[1][79]);
    z++;
    nodes[388].father = nodes + 104;

    nodes[388].terminal = 1;
    nodes[388].outcome = z;
    z->whichnode = nodes + 388;
    z->pay[0] = ratfromi(pay[0][80]);
    z->pay[1] = ratfromi(pay[1][80]);
    z++;
    nodes[389].father = nodes + 102;

    nodes[389].terminal = 1;
    nodes[389].outcome = z;
    z->whichnode = nodes + 389;
    z->pay[0] = ratfromi(pay[0][81]);
    z->pay[1] = ratfromi(pay[1][81]);
    z++;
    nodes[390].father = nodes + 98;

    nodes[390].terminal = 1;
    nodes[390].outcome = z;
    z->whichnode = nodes + 390;
    z->pay[0] = ratfromi(pay[0][82]);
    z->pay[1] = ratfromi(pay[1][82]);
    z++;
    nodes[391].father = nodes + 97;

    nodes[391].terminal = 1;
    nodes[391].outcome = z;
    z->whichnode = nodes + 391;
    z->pay[0] = ratfromi(pay[0][83]);
    z->pay[1] = ratfromi(pay[1][83]);
    z++;
    nodes[392].father = nodes + 110;

    nodes[392].terminal = 1;
    nodes[392].outcome = z;
    z->whichnode = nodes + 392;
    z->pay[0] = ratfromi(pay[0][84]);
    z->pay[1] = ratfromi(pay[1][84]);
    z++;
    nodes[393].father = nodes + 110;

    nodes[393].terminal = 1;
    nodes[393].outcome = z;
    z->whichnode = nodes + 393;
    z->pay[0] = ratfromi(pay[0][85]);
    z->pay[1] = ratfromi(pay[1][85]);
    z++;
    nodes[394].father = nodes + 113;

    nodes[394].terminal = 1;
    nodes[394].outcome = z;
    z->whichnode = nodes + 394;
    z->pay[0] = ratfromi(pay[0][86]);
    z->pay[1] = ratfromi(pay[1][86]);
    z++;
    nodes[395].father = nodes + 113;

    nodes[395].terminal = 1;
    nodes[395].outcome = z;
    z->whichnode = nodes + 395;
    z->pay[0] = ratfromi(pay[0][87]);
    z->pay[1] = ratfromi(pay[1][87]);
    z++;
    nodes[396].father = nodes + 111;

    nodes[396].terminal = 1;
    nodes[396].outcome = z;
    z->whichnode = nodes + 396;
    z->pay[0] = ratfromi(pay[0][88]);
    z->pay[1] = ratfromi(pay[1][88]);
    z++;
    nodes[397].father = nodes + 107;

    nodes[397].terminal = 1;
    nodes[397].outcome = z;
    z->whichnode = nodes + 397;
    z->pay[0] = ratfromi(pay[0][89]);
    z->pay[1] = ratfromi(pay[1][89]);
    z++;
    nodes[398].father = nodes + 106;

    nodes[398].terminal = 1;
    nodes[398].outcome = z;
    z->whichnode = nodes + 398;
    z->pay[0] = ratfromi(pay[0][90]);
    z->pay[1] = ratfromi(pay[1][90]);
    z++;
    nodes[399].father = nodes + 118;

    nodes[399].terminal = 1;
    nodes[399].outcome = z;
    z->whichnode = nodes + 399;
    z->pay[0] = ratfromi(pay[0][91]);
    z->pay[1] = ratfromi(pay[1][91]);
    z++;
    nodes[400].father = nodes + 118;

    nodes[400].terminal = 1;
    nodes[400].outcome = z;
    z->whichnode = nodes + 400;
    z->pay[0] = ratfromi(pay[0][92]);
    z->pay[1] = ratfromi(pay[1][92]);
    z++;
    nodes[401].father = nodes + 121;

    nodes[401].terminal = 1;
    nodes[401].outcome = z;
    z->whichnode = nodes + 401;
    z->pay[0] = ratfromi(pay[0][93]);
    z->pay[1] = ratfromi(pay[1][93]);
    z++;
    nodes[402].father = nodes + 121;

    nodes[402].terminal = 1;
    nodes[402].outcome = z;
    z->whichnode = nodes + 402;
    z->pay[0] = ratfromi(pay[0][94]);
    z->pay[1] = ratfromi(pay[1][94]);
    z++;
    nodes[403].father = nodes + 119;

    nodes[403].terminal = 1;
    nodes[403].outcome = z;
    z->whichnode = nodes + 403;
    z->pay[0] = ratfromi(pay[0][95]);
    z->pay[1] = ratfromi(pay[1][95]);
    z++;
    nodes[404].father = nodes + 115;

    nodes[404].terminal = 1;
    nodes[404].outcome = z;
    z->whichnode = nodes + 404;
    z->pay[0] = ratfromi(pay[0][96]);
    z->pay[1] = ratfromi(pay[1][96]);
    z++;
    nodes[405].father = nodes + 114;

    nodes[405].terminal = 1;
    nodes[405].outcome = z;
    z->whichnode = nodes + 405;
    z->pay[0] = ratfromi(pay[0][97]);
    z->pay[1] = ratfromi(pay[1][97]);
    z++;
    nodes[406].father = nodes + 126;

    nodes[406].terminal = 1;
    nodes[406].outcome = z;
    z->whichnode = nodes + 406;
    z->pay[0] = ratfromi(pay[0][98]);
    z->pay[1] = ratfromi(pay[1][98]);
    z++;
    nodes[407].father = nodes + 126;

    nodes[407].terminal = 1;
    nodes[407].outcome = z;
    z->whichnode = nodes + 407;
    z->pay[0] = ratfromi(pay[0][99]);
    z->pay[1] = ratfromi(pay[1][99]);
    z++;
    nodes[408].father = nodes + 129;

    nodes[408].terminal = 1;
    nodes[408].outcome = z;
    z->whichnode = nodes + 408;
    z->pay[0] = ratfromi(pay[0][100]);
    z->pay[1] = ratfromi(pay[1][100]);
    z++;
    nodes[409].father = nodes + 129;

    nodes[409].terminal = 1;
    nodes[409].outcome = z;
    z->whichnode = nodes + 409;
    z->pay[0] = ratfromi(pay[0][101]);
    z->pay[1] = ratfromi(pay[1][101]);
    z++;
    nodes[410].father = nodes + 127;

    nodes[410].terminal = 1;
    nodes[410].outcome = z;
    z->whichnode = nodes + 410;
    z->pay[0] = ratfromi(pay[0][102]);
    z->pay[1] = ratfromi(pay[1][102]);
    z++;
    nodes[411].father = nodes + 123;

    nodes[411].terminal = 1;
    nodes[411].outcome = z;
    z->whichnode = nodes + 411;
    z->pay[0] = ratfromi(pay[0][103]);
    z->pay[1] = ratfromi(pay[1][103]);
    z++;
    nodes[412].father = nodes + 122;

    nodes[412].terminal = 1;
    nodes[412].outcome = z;
    z->whichnode = nodes + 412;
    z->pay[0] = ratfromi(pay[0][104]);
    z->pay[1] = ratfromi(pay[1][104]);
    z++;
    nodes[413].father = nodes + 135;

    nodes[413].terminal = 1;
    nodes[413].outcome = z;
    z->whichnode = nodes + 413;
    z->pay[0] = ratfromi(pay[0][105]);
    z->pay[1] = ratfromi(pay[1][105]);
    z++;
    nodes[414].father = nodes + 135;

    nodes[414].terminal = 1;
    nodes[414].outcome = z;
    z->whichnode = nodes + 414;
    z->pay[0] = ratfromi(pay[0][106]);
    z->pay[1] = ratfromi(pay[1][106]);
    z++;
    nodes[415].father = nodes + 138;

    nodes[415].terminal = 1;
    nodes[415].outcome = z;
    z->whichnode = nodes + 415;
    z->pay[0] = ratfromi(pay[0][107]);
    z->pay[1] = ratfromi(pay[1][107]);
    z++;
    nodes[416].father = nodes + 138;

    nodes[416].terminal = 1;
    nodes[416].outcome = z;
    z->whichnode = nodes + 416;
    z->pay[0] = ratfromi(pay[0][108]);
    z->pay[1] = ratfromi(pay[1][108]);
    z++;
    nodes[417].father = nodes + 136;

    nodes[417].terminal = 1;
    nodes[417].outcome = z;
    z->whichnode = nodes + 417;
    z->pay[0] = ratfromi(pay[0][109]);
    z->pay[1] = ratfromi(pay[1][109]);
    z++;
    nodes[418].father = nodes + 132;

    nodes[418].terminal = 1;
    nodes[418].outcome = z;
    z->whichnode = nodes + 418;
    z->pay[0] = ratfromi(pay[0][110]);
    z->pay[1] = ratfromi(pay[1][110]);
    z++;
    nodes[419].father = nodes + 131;

    nodes[419].terminal = 1;
    nodes[419].outcome = z;
    z->whichnode = nodes + 419;
    z->pay[0] = ratfromi(pay[0][111]);
    z->pay[1] = ratfromi(pay[1][111]);
    z++;
    nodes[420].father = nodes + 143;

    nodes[420].terminal = 1;
    nodes[420].outcome = z;
    z->whichnode = nodes + 420;
    z->pay[0] = ratfromi(pay[0][112]);
    z->pay[1] = ratfromi(pay[1][112]);
    z++;
    nodes[421].father = nodes + 143;

    nodes[421].terminal = 1;
    nodes[421].outcome = z;
    z->whichnode = nodes + 421;
    z->pay[0] = ratfromi(pay[0][113]);
    z->pay[1] = ratfromi(pay[1][113]);
    z++;
    nodes[422].father = nodes + 146;

    nodes[422].terminal = 1;
    nodes[422].outcome = z;
    z->whichnode = nodes + 422;
    z->pay[0] = ratfromi(pay[0][114]);
    z->pay[1] = ratfromi(pay[1][114]);
    z++;
    nodes[423].father = nodes + 146;

    nodes[423].terminal = 1;
    nodes[423].outcome = z;
    z->whichnode = nodes + 423;
    z->pay[0] = ratfromi(pay[0][115]);
    z->pay[1] = ratfromi(pay[1][115]);
    z++;
    nodes[424].father = nodes + 144;

    nodes[424].terminal = 1;
    nodes[424].outcome = z;
    z->whichnode = nodes + 424;
    z->pay[0] = ratfromi(pay[0][116]);
    z->pay[1] = ratfromi(pay[1][116]);
    z++;
    nodes[425].father = nodes + 140;

    nodes[425].terminal = 1;
    nodes[425].outcome = z;
    z->whichnode = nodes + 425;
    z->pay[0] = ratfromi(pay[0][117]);
    z->pay[1] = ratfromi(pay[1][117]);
    z++;
    nodes[426].father = nodes + 139;

    nodes[426].terminal = 1;
    nodes[426].outcome = z;
    z->whichnode = nodes + 426;
    z->pay[0] = ratfromi(pay[0][118]);
    z->pay[1] = ratfromi(pay[1][118]);
    z++;
    nodes[427].father = nodes + 151;

    nodes[427].terminal = 1;
    nodes[427].outcome = z;
    z->whichnode = nodes + 427;
    z->pay[0] = ratfromi(pay[0][119]);
    z->pay[1] = ratfromi(pay[1][119]);
    z++;
    nodes[428].father = nodes + 151;

    nodes[428].terminal = 1;
    nodes[428].outcome = z;
    z->whichnode = nodes + 428;
    z->pay[0] = ratfromi(pay[0][120]);
    z->pay[1] = ratfromi(pay[1][120]);
    z++;
    nodes[429].father = nodes + 154;

    nodes[429].terminal = 1;
    nodes[429].outcome = z;
    z->whichnode = nodes + 429;
    z->pay[0] = ratfromi(pay[0][121]);
    z->pay[1] = ratfromi(pay[1][121]);
    z++;
    nodes[430].father = nodes + 154;

    nodes[430].terminal = 1;
    nodes[430].outcome = z;
    z->whichnode = nodes + 430;
    z->pay[0] = ratfromi(pay[0][122]);
    z->pay[1] = ratfromi(pay[1][122]);
    z++;
    nodes[431].father = nodes + 152;

    nodes[431].terminal = 1;
    nodes[431].outcome = z;
    z->whichnode = nodes + 431;
    z->pay[0] = ratfromi(pay[0][123]);
    z->pay[1] = ratfromi(pay[1][123]);
    z++;
    nodes[432].father = nodes + 148;

    nodes[432].terminal = 1;
    nodes[432].outcome = z;
    z->whichnode = nodes + 432;
    z->pay[0] = ratfromi(pay[0][124]);
    z->pay[1] = ratfromi(pay[1][124]);
    z++;
    nodes[433].father = nodes + 147;

    nodes[433].terminal = 1;
    nodes[433].outcome = z;
    z->whichnode = nodes + 433;
    z->pay[0] = ratfromi(pay[0][125]);
    z->pay[1] = ratfromi(pay[1][125]);
    z++;
    nodes[434].father = nodes + 162;

    nodes[434].terminal = 1;
    nodes[434].outcome = z;
    z->whichnode = nodes + 434;
    z->pay[0] = ratfromi(pay[0][126]);
    z->pay[1] = ratfromi(pay[1][126]);
    z++;
    nodes[435].father = nodes + 162;

    nodes[435].terminal = 1;
    nodes[435].outcome = z;
    z->whichnode = nodes + 435;
    z->pay[0] = ratfromi(pay[0][127]);
    z->pay[1] = ratfromi(pay[1][127]);
    z++;
    nodes[436].father = nodes + 165;

    nodes[436].terminal = 1;
    nodes[436].outcome = z;
    z->whichnode = nodes + 436;
    z->pay[0] = ratfromi(pay[0][128]);
    z->pay[1] = ratfromi(pay[1][128]);
    z++;
    nodes[437].father = nodes + 165;

    nodes[437].terminal = 1;
    nodes[437].outcome = z;
    z->whichnode = nodes + 437;
    z->pay[0] = ratfromi(pay[0][129]);
    z->pay[1] = ratfromi(pay[1][129]);
    z++;
    nodes[438].father = nodes + 163;

    nodes[438].terminal = 1;
    nodes[438].outcome = z;
    z->whichnode = nodes + 438;
    z->pay[0] = ratfromi(pay[0][130]);
    z->pay[1] = ratfromi(pay[1][130]);
    z++;
    nodes[439].father = nodes + 159;

    nodes[439].terminal = 1;
    nodes[439].outcome = z;
    z->whichnode = nodes + 439;
    z->pay[0] = ratfromi(pay[0][131]);
    z->pay[1] = ratfromi(pay[1][131]);
    z++;
    nodes[440].father = nodes + 158;

    nodes[440].terminal = 1;
    nodes[440].outcome = z;
    z->whichnode = nodes + 440;
    z->pay[0] = ratfromi(pay[0][132]);
    z->pay[1] = ratfromi(pay[1][132]);
    z++;
    nodes[441].father = nodes + 170;

    nodes[441].terminal = 1;
    nodes[441].outcome = z;
    z->whichnode = nodes + 441;
    z->pay[0] = ratfromi(pay[0][133]);
    z->pay[1] = ratfromi(pay[1][133]);
    z++;
    nodes[442].father = nodes + 170;

    nodes[442].terminal = 1;
    nodes[442].outcome = z;
    z->whichnode = nodes + 442;
    z->pay[0] = ratfromi(pay[0][134]);
    z->pay[1] = ratfromi(pay[1][134]);
    z++;
    nodes[443].father = nodes + 173;

    nodes[443].terminal = 1;
    nodes[443].outcome = z;
    z->whichnode = nodes + 443;
    z->pay[0] = ratfromi(pay[0][135]);
    z->pay[1] = ratfromi(pay[1][135]);
    z++;
    nodes[444].father = nodes + 173;

    nodes[444].terminal = 1;
    nodes[444].outcome = z;
    z->whichnode = nodes + 444;
    z->pay[0] = ratfromi(pay[0][136]);
    z->pay[1] = ratfromi(pay[1][136]);
    z++;
    nodes[445].father = nodes + 171;

    nodes[445].terminal = 1;
    nodes[445].outcome = z;
    z->whichnode = nodes + 445;
    z->pay[0] = ratfromi(pay[0][137]);
    z->pay[1] = ratfromi(pay[1][137]);
    z++;
    nodes[446].father = nodes + 167;

    nodes[446].terminal = 1;
    nodes[446].outcome = z;
    z->whichnode = nodes + 446;
    z->pay[0] = ratfromi(pay[0][138]);
    z->pay[1] = ratfromi(pay[1][138]);
    z++;
    nodes[447].father = nodes + 166;

    nodes[447].terminal = 1;
    nodes[447].outcome = z;
    z->whichnode = nodes + 447;
    z->pay[0] = ratfromi(pay[0][139]);
    z->pay[1] = ratfromi(pay[1][139]);
    z++;
    nodes[448].father = nodes + 178;

    nodes[448].terminal = 1;
    nodes[448].outcome = z;
    z->whichnode = nodes + 448;
    z->pay[0] = ratfromi(pay[0][140]);
    z->pay[1] = ratfromi(pay[1][140]);
    z++;
    nodes[449].father = nodes + 178;

    nodes[449].terminal = 1;
    nodes[449].outcome = z;
    z->whichnode = nodes + 449;
    z->pay[0] = ratfromi(pay[0][141]);
    z->pay[1] = ratfromi(pay[1][141]);
    z++;
    nodes[450].father = nodes + 181;

    nodes[450].terminal = 1;
    nodes[450].outcome = z;
    z->whichnode = nodes + 450;
    z->pay[0] = ratfromi(pay[0][142]);
    z->pay[1] = ratfromi(pay[1][142]);
    z++;
    nodes[451].father = nodes + 181;

    nodes[451].terminal = 1;
    nodes[451].outcome = z;
    z->whichnode = nodes + 451;
    z->pay[0] = ratfromi(pay[0][143]);
    z->pay[1] = ratfromi(pay[1][143]);
    z++;
    nodes[452].father = nodes + 179;

    nodes[452].terminal = 1;
    nodes[452].outcome = z;
    z->whichnode = nodes + 452;
    z->pay[0] = ratfromi(pay[0][144]);
    z->pay[1] = ratfromi(pay[1][144]);
    z++;
    nodes[453].father = nodes + 175;

    nodes[453].terminal = 1;
    nodes[453].outcome = z;
    z->whichnode = nodes + 453;
    z->pay[0] = ratfromi(pay[0][145]);
    z->pay[1] = ratfromi(pay[1][145]);
    z++;
    nodes[454].father = nodes + 174;

    nodes[454].terminal = 1;
    nodes[454].outcome = z;
    z->whichnode = nodes + 454;
    z->pay[0] = ratfromi(pay[0][146]);
    z->pay[1] = ratfromi(pay[1][146]);
    z++;
    nodes[455].father = nodes + 187;

    nodes[455].terminal = 1;
    nodes[455].outcome = z;
    z->whichnode = nodes + 455;
    z->pay[0] = ratfromi(pay[0][147]);
    z->pay[1] = ratfromi(pay[1][147]);
    z++;
    nodes[456].father = nodes + 187;

    nodes[456].terminal = 1;
    nodes[456].outcome = z;
    z->whichnode = nodes + 456;
    z->pay[0] = ratfromi(pay[0][148]);
    z->pay[1] = ratfromi(pay[1][148]);
    z++;
    nodes[457].father = nodes + 190;

    nodes[457].terminal = 1;
    nodes[457].outcome = z;
    z->whichnode = nodes + 457;
    z->pay[0] = ratfromi(pay[0][149]);
    z->pay[1] = ratfromi(pay[1][149]);
    z++;
    nodes[458].father = nodes + 190;

    nodes[458].terminal = 1;
    nodes[458].outcome = z;
    z->whichnode = nodes + 458;
    z->pay[0] = ratfromi(pay[0][150]);
    z->pay[1] = ratfromi(pay[1][150]);
    z++;
    nodes[459].father = nodes + 188;

    nodes[459].terminal = 1;
    nodes[459].outcome = z;
    z->whichnode = nodes + 459;
    z->pay[0] = ratfromi(pay[0][151]);
    z->pay[1] = ratfromi(pay[1][151]);
    z++;
    nodes[460].father = nodes + 184;

    nodes[460].terminal = 1;
    nodes[460].outcome = z;
    z->whichnode = nodes + 460;
    z->pay[0] = ratfromi(pay[0][152]);
    z->pay[1] = ratfromi(pay[1][152]);
    z++;
    nodes[461].father = nodes + 183;

    nodes[461].terminal = 1;
    nodes[461].outcome = z;
    z->whichnode = nodes + 461;
    z->pay[0] = ratfromi(pay[0][153]);
    z->pay[1] = ratfromi(pay[1][153]);
    z++;
    nodes[462].father = nodes + 195;

    nodes[462].terminal = 1;
    nodes[462].outcome = z;
    z->whichnode = nodes + 462;
    z->pay[0] = ratfromi(pay[0][154]);
    z->pay[1] = ratfromi(pay[1][154]);
    z++;
    nodes[463].father = nodes + 195;

    nodes[463].terminal = 1;
    nodes[463].outcome = z;
    z->whichnode = nodes + 463;
    z->pay[0] = ratfromi(pay[0][155]);
    z->pay[1] = ratfromi(pay[1][155]);
    z++;
    nodes[464].father = nodes + 198;

    nodes[464].terminal = 1;
    nodes[464].outcome = z;
    z->whichnode = nodes + 464;
    z->pay[0] = ratfromi(pay[0][156]);
    z->pay[1] = ratfromi(pay[1][156]);
    z++;
    nodes[465].father = nodes + 198;

    nodes[465].terminal = 1;
    nodes[465].outcome = z;
    z->whichnode = nodes + 465;
    z->pay[0] = ratfromi(pay[0][157]);
    z->pay[1] = ratfromi(pay[1][157]);
    z++;
    nodes[466].father = nodes + 196;

    nodes[466].terminal = 1;
    nodes[466].outcome = z;
    z->whichnode = nodes + 466;
    z->pay[0] = ratfromi(pay[0][158]);
    z->pay[1] = ratfromi(pay[1][158]);
    z++;
    nodes[467].father = nodes + 192;

    nodes[467].terminal = 1;
    nodes[467].outcome = z;
    z->whichnode = nodes + 467;
    z->pay[0] = ratfromi(pay[0][159]);
    z->pay[1] = ratfromi(pay[1][159]);
    z++;
    nodes[468].father = nodes + 191;

    nodes[468].terminal = 1;
    nodes[468].outcome = z;
    z->whichnode = nodes + 468;
    z->pay[0] = ratfromi(pay[0][160]);
    z->pay[1] = ratfromi(pay[1][160]);
    z++;
    nodes[469].father = nodes + 203;

    nodes[469].terminal = 1;
    nodes[469].outcome = z;
    z->whichnode = nodes + 469;
    z->pay[0] = ratfromi(pay[0][161]);
    z->pay[1] = ratfromi(pay[1][161]);
    z++;
    nodes[470].father = nodes + 203;

    nodes[470].terminal = 1;
    nodes[470].outcome = z;
    z->whichnode = nodes + 470;
    z->pay[0] = ratfromi(pay[0][162]);
    z->pay[1] = ratfromi(pay[1][162]);
    z++;
    nodes[471].father = nodes + 206;

    nodes[471].terminal = 1;
    nodes[471].outcome = z;
    z->whichnode = nodes + 471;
    z->pay[0] = ratfromi(pay[0][163]);
    z->pay[1] = ratfromi(pay[1][163]);
    z++;
    nodes[472].father = nodes + 206;

    nodes[472].terminal = 1;
    nodes[472].outcome = z;
    z->whichnode = nodes + 472;
    z->pay[0] = ratfromi(pay[0][164]);
    z->pay[1] = ratfromi(pay[1][164]);
    z++;
    nodes[473].father = nodes + 204;

    nodes[473].terminal = 1;
    nodes[473].outcome = z;
    z->whichnode = nodes + 473;
    z->pay[0] = ratfromi(pay[0][165]);
    z->pay[1] = ratfromi(pay[1][165]);
    z++;
    nodes[474].father = nodes + 200;

    nodes[474].terminal = 1;
    nodes[474].outcome = z;
    z->whichnode = nodes + 474;
    z->pay[0] = ratfromi(pay[0][166]);
    z->pay[1] = ratfromi(pay[1][166]);
    z++;
    nodes[475].father = nodes + 199;

    nodes[475].terminal = 1;
    nodes[475].outcome = z;
    z->whichnode = nodes + 475;
    z->pay[0] = ratfromi(pay[0][167]);
    z->pay[1] = ratfromi(pay[1][167]);
    z++;
    nodes[476].father = nodes + 212;

    nodes[476].terminal = 1;
    nodes[476].outcome = z;
    z->whichnode = nodes + 476;
    z->pay[0] = ratfromi(pay[0][168]);
    z->pay[1] = ratfromi(pay[1][168]);
    z++;
    nodes[477].father = nodes + 212;

    nodes[477].terminal = 1;
    nodes[477].outcome = z;
    z->whichnode = nodes + 477;
    z->pay[0] = ratfromi(pay[0][169]);
    z->pay[1] = ratfromi(pay[1][169]);
    z++;
    nodes[478].father = nodes + 215;

    nodes[478].terminal = 1;
    nodes[478].outcome = z;
    z->whichnode = nodes + 478;
    z->pay[0] = ratfromi(pay[0][170]);
    z->pay[1] = ratfromi(pay[1][170]);
    z++;
    nodes[479].father = nodes + 215;

    nodes[479].terminal = 1;
    nodes[479].outcome = z;
    z->whichnode = nodes + 479;
    z->pay[0] = ratfromi(pay[0][171]);
    z->pay[1] = ratfromi(pay[1][171]);
    z++;
    nodes[480].father = nodes + 213;

    nodes[480].terminal = 1;
    nodes[480].outcome = z;
    z->whichnode = nodes + 480;
    z->pay[0] = ratfromi(pay[0][172]);
    z->pay[1] = ratfromi(pay[1][172]);
    z++;
    nodes[481].father = nodes + 209;

    nodes[481].terminal = 1;
    nodes[481].outcome = z;
    z->whichnode = nodes + 481;
    z->pay[0] = ratfromi(pay[0][173]);
    z->pay[1] = ratfromi(pay[1][173]);
    z++;
    nodes[482].father = nodes + 208;

    nodes[482].terminal = 1;
    nodes[482].outcome = z;
    z->whichnode = nodes + 482;
    z->pay[0] = ratfromi(pay[0][174]);
    z->pay[1] = ratfromi(pay[1][174]);
    z++;
    nodes[483].father = nodes + 220;

    nodes[483].terminal = 1;
    nodes[483].outcome = z;
    z->whichnode = nodes + 483;
    z->pay[0] = ratfromi(pay[0][175]);
    z->pay[1] = ratfromi(pay[1][175]);
    z++;
    nodes[484].father = nodes + 220;

    nodes[484].terminal = 1;
    nodes[484].outcome = z;
    z->whichnode = nodes + 484;
    z->pay[0] = ratfromi(pay[0][176]);
    z->pay[1] = ratfromi(pay[1][176]);
    z++;
    nodes[485].father = nodes + 223;

    nodes[485].terminal = 1;
    nodes[485].outcome = z;
    z->whichnode = nodes + 485;
    z->pay[0] = ratfromi(pay[0][177]);
    z->pay[1] = ratfromi(pay[1][177]);
    z++;
    nodes[486].father = nodes + 223;

    nodes[486].terminal = 1;
    nodes[486].outcome = z;
    z->whichnode = nodes + 486;
    z->pay[0] = ratfromi(pay[0][178]);
    z->pay[1] = ratfromi(pay[1][178]);
    z++;
    nodes[487].father = nodes + 221;

    nodes[487].terminal = 1;
    nodes[487].outcome = z;
    z->whichnode = nodes + 487;
    z->pay[0] = ratfromi(pay[0][179]);
    z->pay[1] = ratfromi(pay[1][179]);
    z++;
    nodes[488].father = nodes + 217;

    nodes[488].terminal = 1;
    nodes[488].outcome = z;
    z->whichnode = nodes + 488;
    z->pay[0] = ratfromi(pay[0][180]);
    z->pay[1] = ratfromi(pay[1][180]);
    z++;
    nodes[489].father = nodes + 216;

    nodes[489].terminal = 1;
    nodes[489].outcome = z;
    z->whichnode = nodes + 489;
    z->pay[0] = ratfromi(pay[0][181]);
    z->pay[1] = ratfromi(pay[1][181]);
    z++;
    nodes[490].father = nodes + 228;

    nodes[490].terminal = 1;
    nodes[490].outcome = z;
    z->whichnode = nodes + 490;
    z->pay[0] = ratfromi(pay[0][182]);
    z->pay[1] = ratfromi(pay[1][182]);
    z++;
    nodes[491].father = nodes + 228;

    nodes[491].terminal = 1;
    nodes[491].outcome = z;
    z->whichnode = nodes + 491;
    z->pay[0] = ratfromi(pay[0][183]);
    z->pay[1] = ratfromi(pay[1][183]);
    z++;
    nodes[492].father = nodes + 231;

    nodes[492].terminal = 1;
    nodes[492].outcome = z;
    z->whichnode = nodes + 492;
    z->pay[0] = ratfromi(pay[0][184]);
    z->pay[1] = ratfromi(pay[1][184]);
    z++;
    nodes[493].father = nodes + 231;

    nodes[493].terminal = 1;
    nodes[493].outcome = z;
    z->whichnode = nodes + 493;
    z->pay[0] = ratfromi(pay[0][185]);
    z->pay[1] = ratfromi(pay[1][185]);
    z++;
    nodes[494].father = nodes + 229;

    nodes[494].terminal = 1;
    nodes[494].outcome = z;
    z->whichnode = nodes + 494;
    z->pay[0] = ratfromi(pay[0][186]);
    z->pay[1] = ratfromi(pay[1][186]);
    z++;
    nodes[495].father = nodes + 225;

    nodes[495].terminal = 1;
    nodes[495].outcome = z;
    z->whichnode = nodes + 495;
    z->pay[0] = ratfromi(pay[0][187]);
    z->pay[1] = ratfromi(pay[1][187]);
    z++;
    nodes[496].father = nodes + 224;

    nodes[496].terminal = 1;
    nodes[496].outcome = z;
    z->whichnode = nodes + 496;
    z->pay[0] = ratfromi(pay[0][188]);
    z->pay[1] = ratfromi(pay[1][188]);
    z++;
    nodes[497].father = nodes + 238;

    nodes[497].terminal = 1;
    nodes[497].outcome = z;
    z->whichnode = nodes + 497;
    z->pay[0] = ratfromi(pay[0][189]);
    z->pay[1] = ratfromi(pay[1][189]);
    z++;
    nodes[498].father = nodes + 238;

    nodes[498].terminal = 1;
    nodes[498].outcome = z;
    z->whichnode = nodes + 498;
    z->pay[0] = ratfromi(pay[0][190]);
    z->pay[1] = ratfromi(pay[1][190]);
    z++;
    nodes[499].father = nodes + 241;

    nodes[499].terminal = 1;
    nodes[499].outcome = z;
    z->whichnode = nodes + 499;
    z->pay[0] = ratfromi(pay[0][191]);
    z->pay[1] = ratfromi(pay[1][191]);
    z++;
    nodes[500].father = nodes + 241;

    nodes[500].terminal = 1;
    nodes[500].outcome = z;
    z->whichnode = nodes + 500;
    z->pay[0] = ratfromi(pay[0][192]);
    z->pay[1] = ratfromi(pay[1][192]);
    z++;
    nodes[501].father = nodes + 239;

    nodes[501].terminal = 1;
    nodes[501].outcome = z;
    z->whichnode = nodes + 501;
    z->pay[0] = ratfromi(pay[0][193]);
    z->pay[1] = ratfromi(pay[1][193]);
    z++;
    nodes[502].father = nodes + 235;

    nodes[502].terminal = 1;
    nodes[502].outcome = z;
    z->whichnode = nodes + 502;
    z->pay[0] = ratfromi(pay[0][194]);
    z->pay[1] = ratfromi(pay[1][194]);
    z++;
    nodes[503].father = nodes + 234;

    nodes[503].terminal = 1;
    nodes[503].outcome = z;
    z->whichnode = nodes + 503;
    z->pay[0] = ratfromi(pay[0][195]);
    z->pay[1] = ratfromi(pay[1][195]);
    z++;
    nodes[504].father = nodes + 246;

    nodes[504].terminal = 1;
    nodes[504].outcome = z;
    z->whichnode = nodes + 504;
    z->pay[0] = ratfromi(pay[0][196]);
    z->pay[1] = ratfromi(pay[1][196]);
    z++;
    nodes[505].father = nodes + 246;

    nodes[505].terminal = 1;
    nodes[505].outcome = z;
    z->whichnode = nodes + 505;
    z->pay[0] = ratfromi(pay[0][197]);
    z->pay[1] = ratfromi(pay[1][197]);
    z++;
    nodes[506].father = nodes + 249;

    nodes[506].terminal = 1;
    nodes[506].outcome = z;
    z->whichnode = nodes + 506;
    z->pay[0] = ratfromi(pay[0][198]);
    z->pay[1] = ratfromi(pay[1][198]);
    z++;
    nodes[507].father = nodes + 249;

    nodes[507].terminal = 1;
    nodes[507].outcome = z;
    z->whichnode = nodes + 507;
    z->pay[0] = ratfromi(pay[0][199]);
    z->pay[1] = ratfromi(pay[1][199]);
    z++;
    nodes[508].father = nodes + 247;

    nodes[508].terminal = 1;
    nodes[508].outcome = z;
    z->whichnode = nodes + 508;
    z->pay[0] = ratfromi(pay[0][200]);
    z->pay[1] = ratfromi(pay[1][200]);
    z++;
    nodes[509].father = nodes + 243;

    nodes[509].terminal = 1;
    nodes[509].outcome = z;
    z->whichnode = nodes + 509;
    z->pay[0] = ratfromi(pay[0][201]);
    z->pay[1] = ratfromi(pay[1][201]);
    z++;
    nodes[510].father = nodes + 242;

    nodes[510].terminal = 1;
    nodes[510].outcome = z;
    z->whichnode = nodes + 510;
    z->pay[0] = ratfromi(pay[0][202]);
    z->pay[1] = ratfromi(pay[1][202]);
    z++;
    nodes[511].father = nodes + 254;

    nodes[511].terminal = 1;
    nodes[511].outcome = z;
    z->whichnode = nodes + 511;
    z->pay[0] = ratfromi(pay[0][203]);
    z->pay[1] = ratfromi(pay[1][203]);
    z++;
    nodes[512].father = nodes + 254;

    nodes[512].terminal = 1;
    nodes[512].outcome = z;
    z->whichnode = nodes + 512;
    z->pay[0] = ratfromi(pay[0][204]);
    z->pay[1] = ratfromi(pay[1][204]);
    z++;
    nodes[513].father = nodes + 257;

    nodes[513].terminal = 1;
    nodes[513].outcome = z;
    z->whichnode = nodes + 513;
    z->pay[0] = ratfromi(pay[0][205]);
    z->pay[1] = ratfromi(pay[1][205]);
    z++;
    nodes[514].father = nodes + 257;

    nodes[514].terminal = 1;
    nodes[514].outcome = z;
    z->whichnode = nodes + 514;
    z->pay[0] = ratfromi(pay[0][206]);
    z->pay[1] = ratfromi(pay[1][206]);
    z++;
    nodes[515].father = nodes + 255;

    nodes[515].terminal = 1;
    nodes[515].outcome = z;
    z->whichnode = nodes + 515;
    z->pay[0] = ratfromi(pay[0][207]);
    z->pay[1] = ratfromi(pay[1][207]);
    z++;
    nodes[516].father = nodes + 251;

    nodes[516].terminal = 1;
    nodes[516].outcome = z;
    z->whichnode = nodes + 516;
    z->pay[0] = ratfromi(pay[0][208]);
    z->pay[1] = ratfromi(pay[1][208]);
    z++;
    nodes[517].father = nodes + 250;

    nodes[517].terminal = 1;
    nodes[517].outcome = z;
    z->whichnode = nodes + 517;
    z->pay[0] = ratfromi(pay[0][209]);
    z->pay[1] = ratfromi(pay[1][209]);
    z++;
    nodes[518].father = nodes + 263;

    nodes[518].terminal = 1;
    nodes[518].outcome = z;
    z->whichnode = nodes + 518;
    z->pay[0] = ratfromi(pay[0][210]);
    z->pay[1] = ratfromi(pay[1][210]);
    z++;
    nodes[519].father = nodes + 263;

    nodes[519].terminal = 1;
    nodes[519].outcome = z;
    z->whichnode = nodes + 519;
    z->pay[0] = ratfromi(pay[0][211]);
    z->pay[1] = ratfromi(pay[1][211]);
    z++;
    nodes[520].father = nodes + 266;

    nodes[520].terminal = 1;
    nodes[520].outcome = z;
    z->whichnode = nodes + 520;
    z->pay[0] = ratfromi(pay[0][212]);
    z->pay[1] = ratfromi(pay[1][212]);
    z++;
    nodes[521].father = nodes + 266;

    nodes[521].terminal = 1;
    nodes[521].outcome = z;
    z->whichnode = nodes + 521;
    z->pay[0] = ratfromi(pay[0][213]);
    z->pay[1] = ratfromi(pay[1][213]);
    z++;
    nodes[522].father = nodes + 264;

    nodes[522].terminal = 1;
    nodes[522].outcome = z;
    z->whichnode = nodes + 522;
    z->pay[0] = ratfromi(pay[0][214]);
    z->pay[1] = ratfromi(pay[1][214]);
    z++;
    nodes[523].father = nodes + 260;

    nodes[523].terminal = 1;
    nodes[523].outcome = z;
    z->whichnode = nodes + 523;
    z->pay[0] = ratfromi(pay[0][215]);
    z->pay[1] = ratfromi(pay[1][215]);
    z++;
    nodes[524].father = nodes + 259;

    nodes[524].terminal = 1;
    nodes[524].outcome = z;
    z->whichnode = nodes + 524;
    z->pay[0] = ratfromi(pay[0][216]);
    z->pay[1] = ratfromi(pay[1][216]);
    z++;
    nodes[525].father = nodes + 271;

    nodes[525].terminal = 1;
    nodes[525].outcome = z;
    z->whichnode = nodes + 525;
    z->pay[0] = ratfromi(pay[0][217]);
    z->pay[1] = ratfromi(pay[1][217]);
    z++;
    nodes[526].father = nodes + 271;

    nodes[526].terminal = 1;
    nodes[526].outcome = z;
    z->whichnode = nodes + 526;
    z->pay[0] = ratfromi(pay[0][218]);
    z->pay[1] = ratfromi(pay[1][218]);
    z++;
    nodes[527].father = nodes + 274;

    nodes[527].terminal = 1;
    nodes[527].outcome = z;
    z->whichnode = nodes + 527;
    z->pay[0] = ratfromi(pay[0][219]);
    z->pay[1] = ratfromi(pay[1][219]);
    z++;
    nodes[528].father = nodes + 274;

    nodes[528].terminal = 1;
    nodes[528].outcome = z;
    z->whichnode = nodes + 528;
    z->pay[0] = ratfromi(pay[0][220]);
    z->pay[1] = ratfromi(pay[1][220]);
    z++;
    nodes[529].father = nodes + 272;

    nodes[529].terminal = 1;
    nodes[529].outcome = z;
    z->whichnode = nodes + 529;
    z->pay[0] = ratfromi(pay[0][221]);
    z->pay[1] = ratfromi(pay[1][221]);
    z++;
    nodes[530].father = nodes + 268;

    nodes[530].terminal = 1;
    nodes[530].outcome = z;
    z->whichnode = nodes + 530;
    z->pay[0] = ratfromi(pay[0][222]);
    z->pay[1] = ratfromi(pay[1][222]);
    z++;
    nodes[531].father = nodes + 267;

    nodes[531].terminal = 1;
    nodes[531].outcome = z;
    z->whichnode = nodes + 531;
    z->pay[0] = ratfromi(pay[0][223]);
    z->pay[1] = ratfromi(pay[1][223]);
    z++;
    nodes[532].father = nodes + 279;

    nodes[532].terminal = 1;
    nodes[532].outcome = z;
    z->whichnode = nodes + 532;
    z->pay[0] = ratfromi(pay[0][224]);
    z->pay[1] = ratfromi(pay[1][224]);
    z++;
    nodes[533].father = nodes + 279;

    nodes[533].terminal = 1;
    nodes[533].outcome = z;
    z->whichnode = nodes + 533;
    z->pay[0] = ratfromi(pay[0][225]);
    z->pay[1] = ratfromi(pay[1][225]);
    z++;
    nodes[534].father = nodes + 282;

    nodes[534].terminal = 1;
    nodes[534].outcome = z;
    z->whichnode = nodes + 534;
    z->pay[0] = ratfromi(pay[0][226]);
    z->pay[1] = ratfromi(pay[1][226]);
    z++;
    nodes[535].father = nodes + 282;

    nodes[535].terminal = 1;
    nodes[535].outcome = z;
    z->whichnode = nodes + 535;
    z->pay[0] = ratfromi(pay[0][227]);
    z->pay[1] = ratfromi(pay[1][227]);
    z++;
    nodes[536].father = nodes + 280;

    nodes[536].terminal = 1;
    nodes[536].outcome = z;
    z->whichnode = nodes + 536;
    z->pay[0] = ratfromi(pay[0][228]);
    z->pay[1] = ratfromi(pay[1][228]);
    z++;
    nodes[537].father = nodes + 276;

    nodes[537].terminal = 1;
    nodes[537].outcome = z;
    z->whichnode = nodes + 537;
    z->pay[0] = ratfromi(pay[0][229]);
    z->pay[1] = ratfromi(pay[1][229]);
    z++;
    nodes[538].father = nodes + 275;

    nodes[538].terminal = 1;
    nodes[538].outcome = z;
    z->whichnode = nodes + 538;
    z->pay[0] = ratfromi(pay[0][230]);
    z->pay[1] = ratfromi(pay[1][230]);
    z++;
    nodes[539].father = nodes + 288;

    nodes[539].terminal = 1;
    nodes[539].outcome = z;
    z->whichnode = nodes + 539;
    z->pay[0] = ratfromi(pay[0][231]);
    z->pay[1] = ratfromi(pay[1][231]);
    z++;
    nodes[540].father = nodes + 288;

    nodes[540].terminal = 1;
    nodes[540].outcome = z;
    z->whichnode = nodes + 540;
    z->pay[0] = ratfromi(pay[0][232]);
    z->pay[1] = ratfromi(pay[1][232]);
    z++;
    nodes[541].father = nodes + 291;

    nodes[541].terminal = 1;
    nodes[541].outcome = z;
    z->whichnode = nodes + 541;
    z->pay[0] = ratfromi(pay[0][233]);
    z->pay[1] = ratfromi(pay[1][233]);
    z++;
    nodes[542].father = nodes + 291;

    nodes[542].terminal = 1;
    nodes[542].outcome = z;
    z->whichnode = nodes + 542;
    z->pay[0] = ratfromi(pay[0][234]);
    z->pay[1] = ratfromi(pay[1][234]);
    z++;
    nodes[543].father = nodes + 289;

    nodes[543].terminal = 1;
    nodes[543].outcome = z;
    z->whichnode = nodes + 543;
    z->pay[0] = ratfromi(pay[0][235]);
    z->pay[1] = ratfromi(pay[1][235]);
    z++;
    nodes[544].father = nodes + 285;

    nodes[544].terminal = 1;
    nodes[544].outcome = z;
    z->whichnode = nodes + 544;
    z->pay[0] = ratfromi(pay[0][236]);
    z->pay[1] = ratfromi(pay[1][236]);
    z++;
    nodes[545].father = nodes + 284;

    nodes[545].terminal = 1;
    nodes[545].outcome = z;
    z->whichnode = nodes + 545;
    z->pay[0] = ratfromi(pay[0][237]);
    z->pay[1] = ratfromi(pay[1][237]);
    z++;
    nodes[546].father = nodes + 296;

    nodes[546].terminal = 1;
    nodes[546].outcome = z;
    z->whichnode = nodes + 546;
    z->pay[0] = ratfromi(pay[0][238]);
    z->pay[1] = ratfromi(pay[1][238]);
    z++;
    nodes[547].father = nodes + 296;

    nodes[547].terminal = 1;
    nodes[547].outcome = z;
    z->whichnode = nodes + 547;
    z->pay[0] = ratfromi(pay[0][239]);
    z->pay[1] = ratfromi(pay[1][239]);
    z++;
    nodes[548].father = nodes + 299;

    nodes[548].terminal = 1;
    nodes[548].outcome = z;
    z->whichnode = nodes + 548;
    z->pay[0] = ratfromi(pay[0][240]);
    z->pay[1] = ratfromi(pay[1][240]);
    z++;
    nodes[549].father = nodes + 299;

    nodes[549].terminal = 1;
    nodes[549].outcome = z;
    z->whichnode = nodes + 549;
    z->pay[0] = ratfromi(pay[0][241]);
    z->pay[1] = ratfromi(pay[1][241]);
    z++;
    nodes[550].father = nodes + 297;

    nodes[550].terminal = 1;
    nodes[550].outcome = z;
    z->whichnode = nodes + 550;
    z->pay[0] = ratfromi(pay[0][242]);
    z->pay[1] = ratfromi(pay[1][242]);
    z++;
    nodes[551].father = nodes + 293;

    nodes[551].terminal = 1;
    nodes[551].outcome = z;
    z->whichnode = nodes + 551;
    z->pay[0] = ratfromi(pay[0][243]);
    z->pay[1] = ratfromi(pay[1][243]);
    z++;
    nodes[552].father = nodes + 292;

    nodes[552].terminal = 1;
    nodes[552].outcome = z;
    z->whichnode = nodes + 552;
    z->pay[0] = ratfromi(pay[0][244]);
    z->pay[1] = ratfromi(pay[1][244]);
    z++;
    nodes[553].father = nodes + 304;

    nodes[553].terminal = 1;
    nodes[553].outcome = z;
    z->whichnode = nodes + 553;
    z->pay[0] = ratfromi(pay[0][245]);
    z->pay[1] = ratfromi(pay[1][245]);
    z++;
    nodes[554].father = nodes + 304;

    nodes[554].terminal = 1;
    nodes[554].outcome = z;
    z->whichnode = nodes + 554;
    z->pay[0] = ratfromi(pay[0][246]);
    z->pay[1] = ratfromi(pay[1][246]);
    z++;
    nodes[555].father = nodes + 307;

    nodes[555].terminal = 1;
    nodes[555].outcome = z;
    z->whichnode = nodes + 555;
    z->pay[0] = ratfromi(pay[0][247]);
    z->pay[1] = ratfromi(pay[1][247]);
    z++;
    nodes[556].father = nodes + 307;

    nodes[556].terminal = 1;
    nodes[556].outcome = z;
    z->whichnode = nodes + 556;
    z->pay[0] = ratfromi(pay[0][248]);
    z->pay[1] = ratfromi(pay[1][248]);
    z++;
    nodes[557].father = nodes + 305;

    nodes[557].terminal = 1;
    nodes[557].outcome = z;
    z->whichnode = nodes + 557;
    z->pay[0] = ratfromi(pay[0][249]);
    z->pay[1] = ratfromi(pay[1][249]);
    z++;
    nodes[558].father = nodes + 301;

    nodes[558].terminal = 1;
    nodes[558].outcome = z;
    z->whichnode = nodes + 558;
    z->pay[0] = ratfromi(pay[0][250]);
    z->pay[1] = ratfromi(pay[1][250]);
    z++;
    nodes[559].father = nodes + 300;

    nodes[559].terminal = 1;
    nodes[559].outcome = z;
    z->whichnode = nodes + 559;
    z->pay[0] = ratfromi(pay[0][251]);
    z->pay[1] = ratfromi(pay[1][251]);
    z++;
    nodes[1].iset = isets + 0;
    nodes[2].iset = isets + 1;
    nodes[3].iset = isets + 2;
    nodes[4].iset = isets + 3;
    nodes[5].iset = isets + 11;
    nodes[6].iset = isets + 17;
    nodes[7].iset = isets + 4;
    nodes[8].iset = isets + 12;
    nodes[9].iset = isets + 18;
    nodes[10].iset = isets + 18;
    nodes[11].iset = isets + 5;
    nodes[12].iset = isets + 6;
    nodes[13].iset = isets + 11;
    nodes[14].iset = isets + 19;
    nodes[15].iset = isets + 4;
    nodes[16].iset = isets + 12;
    nodes[17].iset = isets + 20;
    nodes[18].iset = isets + 20;
    nodes[19].iset = isets + 5;
    nodes[20].iset = isets + 6;
    nodes[21].iset = isets + 11;
    nodes[22].iset = isets + 21;
    nodes[23].iset = isets + 4;
    nodes[24].iset = isets + 12;
    nodes[25].iset = isets + 22;
    nodes[26].iset = isets + 22;
    nodes[27].iset = isets + 5;
    nodes[28].iset = isets + 6;
    nodes[29].iset = isets + 3;
    nodes[30].iset = isets + 13;
    nodes[31].iset = isets + 17;
    nodes[32].iset = isets + 4;
    nodes[33].iset = isets + 14;
    nodes[34].iset = isets + 18;
    nodes[35].iset = isets + 18;
    nodes[36].iset = isets + 5;
    nodes[37].iset = isets + 6;
    nodes[38].iset = isets + 13;
    nodes[39].iset = isets + 19;
    nodes[40].iset = isets + 4;
    nodes[41].iset = isets + 14;
    nodes[42].iset = isets + 20;
    nodes[43].iset = isets + 20;
    nodes[44].iset = isets + 5;
    nodes[45].iset = isets + 6;
    nodes[46].iset = isets + 13;
    nodes[47].iset = isets + 21;
    nodes[48].iset = isets + 4;
    nodes[49].iset = isets + 14;
    nodes[50].iset = isets + 22;
    nodes[51].iset = isets + 22;
    nodes[52].iset = isets + 5;
    nodes[53].iset = isets + 6;
    nodes[54].iset = isets + 3;
    nodes[55].iset = isets + 15;
    nodes[56].iset = isets + 17;
    nodes[57].iset = isets + 4;
    nodes[58].iset = isets + 16;
    nodes[59].iset = isets + 18;
    nodes[60].iset = isets + 18;
    nodes[61].iset = isets + 5;
    nodes[62].iset = isets + 6;
    nodes[63].iset = isets + 15;
    nodes[64].iset = isets + 19;
    nodes[65].iset = isets + 4;
    nodes[66].iset = isets + 16;
    nodes[67].iset = isets + 20;
    nodes[68].iset = isets + 20;
    nodes[69].iset = isets + 5;
    nodes[70].iset = isets + 6;
    nodes[71].iset = isets + 15;
    nodes[72].iset = isets + 21;
    nodes[73].iset = isets + 4;
    nodes[74].iset = isets + 16;
    nodes[75].iset = isets + 22;
    nodes[76].iset = isets + 22;
    nodes[77].iset = isets + 5;
    nodes[78].iset = isets + 6;
    nodes[79].iset = isets + 7;
    nodes[80].iset = isets + 8;
    nodes[81].iset = isets + 11;
    nodes[82].iset = isets + 17;
    nodes[83].iset = isets + 4;
    nodes[84].iset = isets + 12;
    nodes[85].iset = isets + 18;
    nodes[86].iset = isets + 18;
    nodes[87].iset = isets + 5;
    nodes[88].iset = isets + 9;
    nodes[89].iset = isets + 11;
    nodes[90].iset = isets + 19;
    nodes[91].iset = isets + 4;
    nodes[92].iset = isets + 12;
    nodes[93].iset = isets + 20;
    nodes[94].iset = isets + 20;
    nodes[95].iset = isets + 5;
    nodes[96].iset = isets + 9;
    nodes[97].iset = isets + 11;
    nodes[98].iset = isets + 21;
    nodes[99].iset = isets + 4;
    nodes[100].iset = isets + 12;
    nodes[101].iset = isets + 22;
    nodes[102].iset = isets + 22;
    nodes[103].iset = isets + 5;
    nodes[104].iset = isets + 9;
    nodes[105].iset = isets + 8;
    nodes[106].iset = isets + 13;
    nodes[107].iset = isets + 17;
    nodes[108].iset = isets + 4;
    nodes[109].iset = isets + 14;
    nodes[110].iset = isets + 18;
    nodes[111].iset = isets + 18;
    nodes[112].iset = isets + 5;
    nodes[113].iset = isets + 9;
    nodes[114].iset = isets + 13;
    nodes[115].iset = isets + 19;
    nodes[116].iset = isets + 4;
    nodes[117].iset = isets + 14;
    nodes[118].iset = isets + 20;
    nodes[119].iset = isets + 20;
    nodes[120].iset = isets + 5;
    nodes[121].iset = isets + 9;
    nodes[122].iset = isets + 13;
    nodes[123].iset = isets + 21;
    nodes[124].iset = isets + 4;
    nodes[125].iset = isets + 14;
    nodes[126].iset = isets + 22;
    nodes[127].iset = isets + 22;
    nodes[128].iset = isets + 5;
    nodes[129].iset = isets + 9;
    nodes[130].iset = isets + 8;
    nodes[131].iset = isets + 15;
    nodes[132].iset = isets + 17;
    nodes[133].iset = isets + 4;
    nodes[134].iset = isets + 16;
    nodes[135].iset = isets + 18;
    nodes[136].iset = isets + 18;
    nodes[137].iset = isets + 5;
    nodes[138].iset = isets + 9;
    nodes[139].iset = isets + 15;
    nodes[140].iset = isets + 19;
    nodes[141].iset = isets + 4;
    nodes[142].iset = isets + 16;
    nodes[143].iset = isets + 20;
    nodes[144].iset = isets + 20;
    nodes[145].iset = isets + 5;
    nodes[146].iset = isets + 9;
    nodes[147].iset = isets + 15;
    nodes[148].iset = isets + 21;
    nodes[149].iset = isets + 4;
    nodes[150].iset = isets + 16;
    nodes[151].iset = isets + 22;
    nodes[152].iset = isets + 22;
    nodes[153].iset = isets + 5;
    nodes[154].iset = isets + 9;
    nodes[155].iset = isets + 10;
    nodes[156].iset = isets + 2;
    nodes[157].iset = isets + 3;
    nodes[158].iset = isets + 11;
    nodes[159].iset = isets + 17;
    nodes[160].iset = isets + 4;
    nodes[161].iset = isets + 12;
    nodes[162].iset = isets + 18;
    nodes[163].iset = isets + 18;
    nodes[164].iset = isets + 5;
    nodes[165].iset = isets + 6;
    nodes[166].iset = isets + 11;
    nodes[167].iset = isets + 19;
    nodes[168].iset = isets + 4;
    nodes[169].iset = isets + 12;
    nodes[170].iset = isets + 20;
    nodes[171].iset = isets + 20;
    nodes[172].iset = isets + 5;
    nodes[173].iset = isets + 6;
    nodes[174].iset = isets + 11;
    nodes[175].iset = isets + 21;
    nodes[176].iset = isets + 4;
    nodes[177].iset = isets + 12;
    nodes[178].iset = isets + 22;
    nodes[179].iset = isets + 22;
    nodes[180].iset = isets + 5;
    nodes[181].iset = isets + 6;
    nodes[182].iset = isets + 3;
    nodes[183].iset = isets + 13;
    nodes[184].iset = isets + 17;
    nodes[185].iset = isets + 4;
    nodes[186].iset = isets + 14;
    nodes[187].iset = isets + 18;
    nodes[188].iset = isets + 18;
    nodes[189].iset = isets + 5;
    nodes[190].iset = isets + 6;
    nodes[191].iset = isets + 13;
    nodes[192].iset = isets + 19;
    nodes[193].iset = isets + 4;
    nodes[194].iset = isets + 14;
    nodes[195].iset = isets + 20;
    nodes[196].iset = isets + 20;
    nodes[197].iset = isets + 5;
    nodes[198].iset = isets + 6;
    nodes[199].iset = isets + 13;
    nodes[200].iset = isets + 21;
    nodes[201].iset = isets + 4;
    nodes[202].iset = isets + 14;
    nodes[203].iset = isets + 22;
    nodes[204].iset = isets + 22;
    nodes[205].iset = isets + 5;
    nodes[206].iset = isets + 6;
    nodes[207].iset = isets + 3;
    nodes[208].iset = isets + 15;
    nodes[209].iset = isets + 17;
    nodes[210].iset = isets + 4;
    nodes[211].iset = isets + 16;
    nodes[212].iset = isets + 18;
    nodes[213].iset = isets + 18;
    nodes[214].iset = isets + 5;
    nodes[215].iset = isets + 6;
    nodes[216].iset = isets + 15;
    nodes[217].iset = isets + 19;
    nodes[218].iset = isets + 4;
    nodes[219].iset = isets + 16;
    nodes[220].iset = isets + 20;
    nodes[221].iset = isets + 20;
    nodes[222].iset = isets + 5;
    nodes[223].iset = isets + 6;
    nodes[224].iset = isets + 15;
    nodes[225].iset = isets + 21;
    nodes[226].iset = isets + 4;
    nodes[227].iset = isets + 16;
    nodes[228].iset = isets + 22;
    nodes[229].iset = isets + 22;
    nodes[230].iset = isets + 5;
    nodes[231].iset = isets + 6;
    nodes[232].iset = isets + 7;
    nodes[233].iset = isets + 8;
    nodes[234].iset = isets + 11;
    nodes[235].iset = isets + 17;
    nodes[236].iset = isets + 4;
    nodes[237].iset = isets + 12;
    nodes[238].iset = isets + 18;
    nodes[239].iset = isets + 18;
    nodes[240].iset = isets + 5;
    nodes[241].iset = isets + 9;
    nodes[242].iset = isets + 11;
    nodes[243].iset = isets + 19;
    nodes[244].iset = isets + 4;
    nodes[245].iset = isets + 12;
    nodes[246].iset = isets + 20;
    nodes[247].iset = isets + 20;
    nodes[248].iset = isets + 5;
    nodes[249].iset = isets + 9;
    nodes[250].iset = isets + 11;
    nodes[251].iset = isets + 21;
    nodes[252].iset = isets + 4;
    nodes[253].iset = isets + 12;
    nodes[254].iset = isets + 22;
    nodes[255].iset = isets + 22;
    nodes[256].iset = isets + 5;
    nodes[257].iset = isets + 9;
    nodes[258].iset = isets + 8;
    nodes[259].iset = isets + 13;
    nodes[260].iset = isets + 17;
    nodes[261].iset = isets + 4;
    nodes[262].iset = isets + 14;
    nodes[263].iset = isets + 18;
    nodes[264].iset = isets + 18;
    nodes[265].iset = isets + 5;
    nodes[266].iset = isets + 9;
    nodes[267].iset = isets + 13;
    nodes[268].iset = isets + 19;
    nodes[269].iset = isets + 4;
    nodes[270].iset = isets + 14;
    nodes[271].iset = isets + 20;
    nodes[272].iset = isets + 20;
    nodes[273].iset = isets + 5;
    nodes[274].iset = isets + 9;
    nodes[275].iset = isets + 13;
    nodes[276].iset = isets + 21;
    nodes[277].iset = isets + 4;
    nodes[278].iset = isets + 14;
    nodes[279].iset = isets + 22;
    nodes[280].iset = isets + 22;
    nodes[281].iset = isets + 5;
    nodes[282].iset = isets + 9;
    nodes[283].iset = isets + 8;
    nodes[284].iset = isets + 15;
    nodes[285].iset = isets + 17;
    nodes[286].iset = isets + 4;
    nodes[287].iset = isets + 16;
    nodes[288].iset = isets + 18;
    nodes[289].iset = isets + 18;
    nodes[290].iset = isets + 5;
    nodes[291].iset = isets + 9;
    nodes[292].iset = isets + 15;
    nodes[293].iset = isets + 19;
    nodes[294].iset = isets + 4;
    nodes[295].iset = isets + 16;
    nodes[296].iset = isets + 20;
    nodes[297].iset = isets + 20;
    nodes[298].iset = isets + 5;
    nodes[299].iset = isets + 9;
    nodes[300].iset = isets + 15;
    nodes[301].iset = isets + 21;
    nodes[302].iset = isets + 4;
    nodes[303].iset = isets + 16;
    nodes[304].iset = isets + 22;
    nodes[305].iset = isets + 22;
    nodes[306].iset = isets + 5;
    nodes[307].iset = isets + 9;
    nodes[2].reachedby = moves + 1;
    nodes[3].reachedby = moves + 3;
    nodes[4].reachedby = moves + 5;
    nodes[5].reachedby = moves + 8;
    nodes[6].reachedby = moves + 26;
    nodes[7].reachedby = moves + 39;
    nodes[8].reachedby = moves + 11;
    nodes[9].reachedby = moves + 28;
    nodes[10].reachedby = moves + 29;
    nodes[11].reachedby = moves + 41;
    nodes[12].reachedby = moves + 12;
    nodes[13].reachedby = moves + 9;
    nodes[14].reachedby = moves + 26;
    nodes[15].reachedby = moves + 43;
    nodes[16].reachedby = moves + 11;
    nodes[17].reachedby = moves + 28;
    nodes[18].reachedby = moves + 29;
    nodes[19].reachedby = moves + 45;
    nodes[20].reachedby = moves + 12;
    nodes[21].reachedby = moves + 10;
    nodes[22].reachedby = moves + 26;
    nodes[23].reachedby = moves + 47;
    nodes[24].reachedby = moves + 11;
    nodes[25].reachedby = moves + 28;
    nodes[26].reachedby = moves + 29;
    nodes[27].reachedby = moves + 49;
    nodes[28].reachedby = moves + 12;
    nodes[29].reachedby = moves + 6;
    nodes[30].reachedby = moves + 8;
    nodes[31].reachedby = moves + 30;
    nodes[32].reachedby = moves + 39;
    nodes[33].reachedby = moves + 11;
    nodes[34].reachedby = moves + 32;
    nodes[35].reachedby = moves + 33;
    nodes[36].reachedby = moves + 41;
    nodes[37].reachedby = moves + 12;
    nodes[38].reachedby = moves + 9;
    nodes[39].reachedby = moves + 30;
    nodes[40].reachedby = moves + 43;
    nodes[41].reachedby = moves + 11;
    nodes[42].reachedby = moves + 32;
    nodes[43].reachedby = moves + 33;
    nodes[44].reachedby = moves + 45;
    nodes[45].reachedby = moves + 12;
    nodes[46].reachedby = moves + 10;
    nodes[47].reachedby = moves + 30;
    nodes[48].reachedby = moves + 47;
    nodes[49].reachedby = moves + 11;
    nodes[50].reachedby = moves + 32;
    nodes[51].reachedby = moves + 33;
    nodes[52].reachedby = moves + 49;
    nodes[53].reachedby = moves + 12;
    nodes[54].reachedby = moves + 7;
    nodes[55].reachedby = moves + 8;
    nodes[56].reachedby = moves + 34;
    nodes[57].reachedby = moves + 39;
    nodes[58].reachedby = moves + 11;
    nodes[59].reachedby = moves + 36;
    nodes[60].reachedby = moves + 37;
    nodes[61].reachedby = moves + 41;
    nodes[62].reachedby = moves + 12;
    nodes[63].reachedby = moves + 9;
    nodes[64].reachedby = moves + 34;
    nodes[65].reachedby = moves + 43;
    nodes[66].reachedby = moves + 11;
    nodes[67].reachedby = moves + 36;
    nodes[68].reachedby = moves + 37;
    nodes[69].reachedby = moves + 45;
    nodes[70].reachedby = moves + 12;
    nodes[71].reachedby = moves + 10;
    nodes[72].reachedby = moves + 34;
    nodes[73].reachedby = moves + 47;
    nodes[74].reachedby = moves + 11;
    nodes[75].reachedby = moves + 36;
    nodes[76].reachedby = moves + 37;
    nodes[77].reachedby = moves + 49;
    nodes[78].reachedby = moves + 12;
    nodes[79].reachedby = moves + 4;
    nodes[80].reachedby = moves + 15;
    nodes[81].reachedby = moves + 18;
    nodes[82].reachedby = moves + 26;
    nodes[83].reachedby = moves + 39;
    nodes[84].reachedby = moves + 11;
    nodes[85].reachedby = moves + 28;
    nodes[86].reachedby = moves + 29;
    nodes[87].reachedby = moves + 41;
    nodes[88].reachedby = moves + 12;
    nodes[89].reachedby = moves + 19;
    nodes[90].reachedby = moves + 26;
    nodes[91].reachedby = moves + 43;
    nodes[92].reachedby = moves + 11;
    nodes[93].reachedby = moves + 28;
    nodes[94].reachedby = moves + 29;
    nodes[95].reachedby = moves + 45;
    nodes[96].reachedby = moves + 12;
    nodes[97].reachedby = moves + 20;
    nodes[98].reachedby = moves + 26;
    nodes[99].reachedby = moves + 47;
    nodes[100].reachedby = moves + 11;
    nodes[101].reachedby = moves + 28;
    nodes[102].reachedby = moves + 29;
    nodes[103].reachedby = moves + 49;
    nodes[104].reachedby = moves + 12;
    nodes[105].reachedby = moves + 16;
    nodes[106].reachedby = moves + 18;
    nodes[107].reachedby = moves + 30;
    nodes[108].reachedby = moves + 39;
    nodes[109].reachedby = moves + 11;
    nodes[110].reachedby = moves + 32;
    nodes[111].reachedby = moves + 33;
    nodes[112].reachedby = moves + 41;
    nodes[113].reachedby = moves + 12;
    nodes[114].reachedby = moves + 19;
    nodes[115].reachedby = moves + 30;
    nodes[116].reachedby = moves + 43;
    nodes[117].reachedby = moves + 11;
    nodes[118].reachedby = moves + 32;
    nodes[119].reachedby = moves + 33;
    nodes[120].reachedby = moves + 45;
    nodes[121].reachedby = moves + 12;
    nodes[122].reachedby = moves + 20;
    nodes[123].reachedby = moves + 30;
    nodes[124].reachedby = moves + 47;
    nodes[125].reachedby = moves + 11;
    nodes[126].reachedby = moves + 32;
    nodes[127].reachedby = moves + 33;
    nodes[128].reachedby = moves + 49;
    nodes[129].reachedby = moves + 12;
    nodes[130].reachedby = moves + 17;
    nodes[131].reachedby = moves + 18;
    nodes[132].reachedby = moves + 34;
    nodes[133].reachedby = moves + 39;
    nodes[134].reachedby = moves + 11;
    nodes[135].reachedby = moves + 36;
    nodes[136].reachedby = moves + 37;
    nodes[137].reachedby = moves + 41;
    nodes[138].reachedby = moves + 12;
    nodes[139].reachedby = moves + 19;
    nodes[140].reachedby = moves + 34;
    nodes[141].reachedby = moves + 43;
    nodes[142].reachedby = moves + 11;
    nodes[143].reachedby = moves + 36;
    nodes[144].reachedby = moves + 37;
    nodes[145].reachedby = moves + 45;
    nodes[146].reachedby = moves + 12;
    nodes[147].reachedby = moves + 20;
    nodes[148].reachedby = moves + 34;
    nodes[149].reachedby = moves + 47;
    nodes[150].reachedby = moves + 11;
    nodes[151].reachedby = moves + 36;
    nodes[152].reachedby = moves + 37;
    nodes[153].reachedby = moves + 49;
    nodes[154].reachedby = moves + 12;
    nodes[155].reachedby = moves + 2;
    nodes[156].reachedby = moves + 23;
    nodes[157].reachedby = moves + 5;
    nodes[158].reachedby = moves + 8;
    nodes[159].reachedby = moves + 26;
    nodes[160].reachedby = moves + 39;
    nodes[161].reachedby = moves + 11;
    nodes[162].reachedby = moves + 28;
    nodes[163].reachedby = moves + 29;
    nodes[164].reachedby = moves + 41;
    nodes[165].reachedby = moves + 12;
    nodes[166].reachedby = moves + 9;
    nodes[167].reachedby = moves + 26;
    nodes[168].reachedby = moves + 43;
    nodes[169].reachedby = moves + 11;
    nodes[170].reachedby = moves + 28;
    nodes[171].reachedby = moves + 29;
    nodes[172].reachedby = moves + 45;
    nodes[173].reachedby = moves + 12;
    nodes[174].reachedby = moves + 10;
    nodes[175].reachedby = moves + 26;
    nodes[176].reachedby = moves + 47;
    nodes[177].reachedby = moves + 11;
    nodes[178].reachedby = moves + 28;
    nodes[179].reachedby = moves + 29;
    nodes[180].reachedby = moves + 49;
    nodes[181].reachedby = moves + 12;
    nodes[182].reachedby = moves + 6;
    nodes[183].reachedby = moves + 8;
    nodes[184].reachedby = moves + 30;
    nodes[185].reachedby = moves + 39;
    nodes[186].reachedby = moves + 11;
    nodes[187].reachedby = moves + 32;
    nodes[188].reachedby = moves + 33;
    nodes[189].reachedby = moves + 41;
    nodes[190].reachedby = moves + 12;
    nodes[191].reachedby = moves + 9;
    nodes[192].reachedby = moves + 30;
    nodes[193].reachedby = moves + 43;
    nodes[194].reachedby = moves + 11;
    nodes[195].reachedby = moves + 32;
    nodes[196].reachedby = moves + 33;
    nodes[197].reachedby = moves + 45;
    nodes[198].reachedby = moves + 12;
    nodes[199].reachedby = moves + 10;
    nodes[200].reachedby = moves + 30;
    nodes[201].reachedby = moves + 47;
    nodes[202].reachedby = moves + 11;
    nodes[203].reachedby = moves + 32;
    nodes[204].reachedby = moves + 33;
    nodes[205].reachedby = moves + 49;
    nodes[206].reachedby = moves + 12;
    nodes[207].reachedby = moves + 7;
    nodes[208].reachedby = moves + 8;
    nodes[209].reachedby = moves + 34;
    nodes[210].reachedby = moves + 39;
    nodes[211].reachedby = moves + 11;
    nodes[212].reachedby = moves + 36;
    nodes[213].reachedby = moves + 37;
    nodes[214].reachedby = moves + 41;
    nodes[215].reachedby = moves + 12;
    nodes[216].reachedby = moves + 9;
    nodes[217].reachedby = moves + 34;
    nodes[218].reachedby = moves + 43;
    nodes[219].reachedby = moves + 11;
    nodes[220].reachedby = moves + 36;
    nodes[221].reachedby = moves + 37;
    nodes[222].reachedby = moves + 45;
    nodes[223].reachedby = moves + 12;
    nodes[224].reachedby = moves + 10;
    nodes[225].reachedby = moves + 34;
    nodes[226].reachedby = moves + 47;
    nodes[227].reachedby = moves + 11;
    nodes[228].reachedby = moves + 36;
    nodes[229].reachedby = moves + 37;
    nodes[230].reachedby = moves + 49;
    nodes[231].reachedby = moves + 12;
    nodes[232].reachedby = moves + 24;
    nodes[233].reachedby = moves + 15;
    nodes[234].reachedby = moves + 18;
    nodes[235].reachedby = moves + 26;
    nodes[236].reachedby = moves + 39;
    nodes[237].reachedby = moves + 11;
    nodes[238].reachedby = moves + 28;
    nodes[239].reachedby = moves + 29;
    nodes[240].reachedby = moves + 41;
    nodes[241].reachedby = moves + 12;
    nodes[242].reachedby = moves + 19;
    nodes[243].reachedby = moves + 26;
    nodes[244].reachedby = moves + 43;
    nodes[245].reachedby = moves + 11;
    nodes[246].reachedby = moves + 28;
    nodes[247].reachedby = moves + 29;
    nodes[248].reachedby = moves + 45;
    nodes[249].reachedby = moves + 12;
    nodes[250].reachedby = moves + 20;
    nodes[251].reachedby = moves + 26;
    nodes[252].reachedby = moves + 47;
    nodes[253].reachedby = moves + 11;
    nodes[254].reachedby = moves + 28;
    nodes[255].reachedby = moves + 29;
    nodes[256].reachedby = moves + 49;
    nodes[257].reachedby = moves + 12;
    nodes[258].reachedby = moves + 16;
    nodes[259].reachedby = moves + 18;
    nodes[260].reachedby = moves + 30;
    nodes[261].reachedby = moves + 39;
    nodes[262].reachedby = moves + 11;
    nodes[263].reachedby = moves + 32;
    nodes[264].reachedby = moves + 33;
    nodes[265].reachedby = moves + 41;
    nodes[266].reachedby = moves + 12;
    nodes[267].reachedby = moves + 19;
    nodes[268].reachedby = moves + 30;
    nodes[269].reachedby = moves + 43;
    nodes[270].reachedby = moves + 11;
    nodes[271].reachedby = moves + 32;
    nodes[272].reachedby = moves + 33;
    nodes[273].reachedby = moves + 45;
    nodes[274].reachedby = moves + 12;
    nodes[275].reachedby = moves + 20;
    nodes[276].reachedby = moves + 30;
    nodes[277].reachedby = moves + 47;
    nodes[278].reachedby = moves + 11;
    nodes[279].reachedby = moves + 32;
    nodes[280].reachedby = moves + 33;
    nodes[281].reachedby = moves + 49;
    nodes[282].reachedby = moves + 12;
    nodes[283].reachedby = moves + 17;
    nodes[284].reachedby = moves + 18;
    nodes[285].reachedby = moves + 34;
    nodes[286].reachedby = moves + 39;
    nodes[287].reachedby = moves + 11;
    nodes[288].reachedby = moves + 36;
    nodes[289].reachedby = moves + 37;
    nodes[290].reachedby = moves + 41;
    nodes[291].reachedby = moves + 12;
    nodes[292].reachedby = moves + 19;
    nodes[293].reachedby = moves + 34;
    nodes[294].reachedby = moves + 43;
    nodes[295].reachedby = moves + 11;
    nodes[296].reachedby = moves + 36;
    nodes[297].reachedby = moves + 37;
    nodes[298].reachedby = moves + 45;
    nodes[299].reachedby = moves + 12;
    nodes[300].reachedby = moves + 20;
    nodes[301].reachedby = moves + 34;
    nodes[302].reachedby = moves + 47;
    nodes[303].reachedby = moves + 11;
    nodes[304].reachedby = moves + 36;
    nodes[305].reachedby = moves + 37;
    nodes[306].reachedby = moves + 49;
    nodes[307].reachedby = moves + 12;
    nodes[308].reachedby = moves + 41;
    nodes[309].reachedby = moves + 42;
    nodes[310].reachedby = moves + 13;
    nodes[311].reachedby = moves + 14;
    nodes[312].reachedby = moves + 42;
    nodes[313].reachedby = moves + 40;
    nodes[314].reachedby = moves + 27;
    nodes[315].reachedby = moves + 45;
    nodes[316].reachedby = moves + 46;
    nodes[317].reachedby = moves + 13;
    nodes[318].reachedby = moves + 14;
    nodes[319].reachedby = moves + 46;
    nodes[320].reachedby = moves + 44;
    nodes[321].reachedby = moves + 27;
    nodes[322].reachedby = moves + 49;
    nodes[323].reachedby = moves + 50;
    nodes[324].reachedby = moves + 13;
    nodes[325].reachedby = moves + 14;
    nodes[326].reachedby = moves + 50;
    nodes[327].reachedby = moves + 48;
    nodes[328].reachedby = moves + 27;
    nodes[329].reachedby = moves + 41;
    nodes[330].reachedby = moves + 42;
    nodes[331].reachedby = moves + 13;
    nodes[332].reachedby = moves + 14;
    nodes[333].reachedby = moves + 42;
    nodes[334].reachedby = moves + 40;
    nodes[335].reachedby = moves + 31;
    nodes[336].reachedby = moves + 45;
    nodes[337].reachedby = moves + 46;
    nodes[338].reachedby = moves + 13;
    nodes[339].reachedby = moves + 14;
    nodes[340].reachedby = moves + 46;
    nodes[341].reachedby = moves + 44;
    nodes[342].reachedby = moves + 31;
    nodes[343].reachedby = moves + 49;
    nodes[344].reachedby = moves + 50;
    nodes[345].reachedby = moves + 13;
    nodes[346].reachedby = moves + 14;
    nodes[347].reachedby = moves + 50;
    nodes[348].reachedby = moves + 48;
    nodes[349].reachedby = moves + 31;
    nodes[350].reachedby = moves + 41;
    nodes[351].reachedby = moves + 42;
    nodes[352].reachedby = moves + 13;
    nodes[353].reachedby = moves + 14;
    nodes[354].reachedby = moves + 42;
    nodes[355].reachedby = moves + 40;
    nodes[356].reachedby = moves + 35;
    nodes[357].reachedby = moves + 45;
    nodes[358].reachedby = moves + 46;
    nodes[359].reachedby = moves + 13;
    nodes[360].reachedby = moves + 14;
    nodes[361].reachedby = moves + 46;
    nodes[362].reachedby = moves + 44;
    nodes[363].reachedby = moves + 35;
    nodes[364].reachedby = moves + 49;
    nodes[365].reachedby = moves + 50;
    nodes[366].reachedby = moves + 13;
    nodes[367].reachedby = moves + 14;
    nodes[368].reachedby = moves + 50;
    nodes[369].reachedby = moves + 48;
    nodes[370].reachedby = moves + 35;
    nodes[371].reachedby = moves + 41;
    nodes[372].reachedby = moves + 42;
    nodes[373].reachedby = moves + 21;
    nodes[374].reachedby = moves + 22;
    nodes[375].reachedby = moves + 42;
    nodes[376].reachedby = moves + 40;
    nodes[377].reachedby = moves + 27;
    nodes[378].reachedby = moves + 45;
    nodes[379].reachedby = moves + 46;
    nodes[380].reachedby = moves + 21;
    nodes[381].reachedby = moves + 22;
    nodes[382].reachedby = moves + 46;
    nodes[383].reachedby = moves + 44;
    nodes[384].reachedby = moves + 27;
    nodes[385].reachedby = moves + 49;
    nodes[386].reachedby = moves + 50;
    nodes[387].reachedby = moves + 21;
    nodes[388].reachedby = moves + 22;
    nodes[389].reachedby = moves + 50;
    nodes[390].reachedby = moves + 48;
    nodes[391].reachedby = moves + 27;
    nodes[392].reachedby = moves + 41;
    nodes[393].reachedby = moves + 42;
    nodes[394].reachedby = moves + 21;
    nodes[395].reachedby = moves + 22;
    nodes[396].reachedby = moves + 42;
    nodes[397].reachedby = moves + 40;
    nodes[398].reachedby = moves + 31;
    nodes[399].reachedby = moves + 45;
    nodes[400].reachedby = moves + 46;
    nodes[401].reachedby = moves + 21;
    nodes[402].reachedby = moves + 22;
    nodes[403].reachedby = moves + 46;
    nodes[404].reachedby = moves + 44;
    nodes[405].reachedby = moves + 31;
    nodes[406].reachedby = moves + 49;
    nodes[407].reachedby = moves + 50;
    nodes[408].reachedby = moves + 21;
    nodes[409].reachedby = moves + 22;
    nodes[410].reachedby = moves + 50;
    nodes[411].reachedby = moves + 48;
    nodes[412].reachedby = moves + 31;
    nodes[413].reachedby = moves + 41;
    nodes[414].reachedby = moves + 42;
    nodes[415].reachedby = moves + 21;
    nodes[416].reachedby = moves + 22;
    nodes[417].reachedby = moves + 42;
    nodes[418].reachedby = moves + 40;
    nodes[419].reachedby = moves + 35;
    nodes[420].reachedby = moves + 45;
    nodes[421].reachedby = moves + 46;
    nodes[422].reachedby = moves + 21;
    nodes[423].reachedby = moves + 22;
    nodes[424].reachedby = moves + 46;
    nodes[425].reachedby = moves + 44;
    nodes[426].reachedby = moves + 35;
    nodes[427].reachedby = moves + 49;
    nodes[428].reachedby = moves + 50;
    nodes[429].reachedby = moves + 21;
    nodes[430].reachedby = moves + 22;
    nodes[431].reachedby = moves + 50;
    nodes[432].reachedby = moves + 48;
    nodes[433].reachedby = moves + 35;
    nodes[434].reachedby = moves + 41;
    nodes[435].reachedby = moves + 42;
    nodes[436].reachedby = moves + 13;
    nodes[437].reachedby = moves + 14;
    nodes[438].reachedby = moves + 42;
    nodes[439].reachedby = moves + 40;
    nodes[440].reachedby = moves + 27;
    nodes[441].reachedby = moves + 45;
    nodes[442].reachedby = moves + 46;
    nodes[443].reachedby = moves + 13;
    nodes[444].reachedby = moves + 14;
    nodes[445].reachedby = moves + 46;
    nodes[446].reachedby = moves + 44;
    nodes[447].reachedby = moves + 27;
    nodes[448].reachedby = moves + 49;
    nodes[449].reachedby = moves + 50;
    nodes[450].reachedby = moves + 13;
    nodes[451].reachedby = moves + 14;
    nodes[452].reachedby = moves + 50;
    nodes[453].reachedby = moves + 48;
    nodes[454].reachedby = moves + 27;
    nodes[455].reachedby = moves + 41;
    nodes[456].reachedby = moves + 42;
    nodes[457].reachedby = moves + 13;
    nodes[458].reachedby = moves + 14;
    nodes[459].reachedby = moves + 42;
    nodes[460].reachedby = moves + 40;
    nodes[461].reachedby = moves + 31;
    nodes[462].reachedby = moves + 45;
    nodes[463].reachedby = moves + 46;
    nodes[464].reachedby = moves + 13;
    nodes[465].reachedby = moves + 14;
    nodes[466].reachedby = moves + 46;
    nodes[467].reachedby = moves + 44;
    nodes[468].reachedby = moves + 31;
    nodes[469].reachedby = moves + 49;
    nodes[470].reachedby = moves + 50;
    nodes[471].reachedby = moves + 13;
    nodes[472].reachedby = moves + 14;
    nodes[473].reachedby = moves + 50;
    nodes[474].reachedby = moves + 48;
    nodes[475].reachedby = moves + 31;
    nodes[476].reachedby = moves + 41;
    nodes[477].reachedby = moves + 42;
    nodes[478].reachedby = moves + 13;
    nodes[479].reachedby = moves + 14;
    nodes[480].reachedby = moves + 42;
    nodes[481].reachedby = moves + 40;
    nodes[482].reachedby = moves + 35;
    nodes[483].reachedby = moves + 45;
    nodes[484].reachedby = moves + 46;
    nodes[485].reachedby = moves + 13;
    nodes[486].reachedby = moves + 14;
    nodes[487].reachedby = moves + 46;
    nodes[488].reachedby = moves + 44;
    nodes[489].reachedby = moves + 35;
    nodes[490].reachedby = moves + 49;
    nodes[491].reachedby = moves + 50;
    nodes[492].reachedby = moves + 13;
    nodes[493].reachedby = moves + 14;
    nodes[494].reachedby = moves + 50;
    nodes[495].reachedby = moves + 48;
    nodes[496].reachedby = moves + 35;
    nodes[497].reachedby = moves + 41;
    nodes[498].reachedby = moves + 42;
    nodes[499].reachedby = moves + 21;
    nodes[500].reachedby = moves + 22;
    nodes[501].reachedby = moves + 42;
    nodes[502].reachedby = moves + 40;
    nodes[503].reachedby = moves + 27;
    nodes[504].reachedby = moves + 45;
    nodes[505].reachedby = moves + 46;
    nodes[506].reachedby = moves + 21;
    nodes[507].reachedby = moves + 22;
    nodes[508].reachedby = moves + 46;
    nodes[509].reachedby = moves + 44;
    nodes[510].reachedby = moves + 27;
    nodes[511].reachedby = moves + 49;
    nodes[512].reachedby = moves + 50;
    nodes[513].reachedby = moves + 21;
    nodes[514].reachedby = moves + 22;
    nodes[515].reachedby = moves + 50;
    nodes[516].reachedby = moves + 48;
    nodes[517].reachedby = moves + 27;
    nodes[518].reachedby = moves + 41;
    nodes[519].reachedby = moves + 42;
    nodes[520].reachedby = moves + 21;
    nodes[521].reachedby = moves + 22;
    nodes[522].reachedby = moves + 42;
    nodes[523].reachedby = moves + 40;
    nodes[524].reachedby = moves + 31;
    nodes[525].reachedby = moves + 45;
    nodes[526].reachedby = moves + 46;
    nodes[527].reachedby = moves + 21;
    nodes[528].reachedby = moves + 22;
    nodes[529].reachedby = moves + 46;
    nodes[530].reachedby = moves + 44;
    nodes[531].reachedby = moves + 31;
    nodes[532].reachedby = moves + 49;
    nodes[533].reachedby = moves + 50;
    nodes[534].reachedby = moves + 21;
    nodes[535].reachedby = moves + 22;
    nodes[536].reachedby = moves + 50;
    nodes[537].reachedby = moves + 48;
    nodes[538].reachedby = moves + 31;
    nodes[539].reachedby = moves + 41;
    nodes[540].reachedby = moves + 42;
    nodes[541].reachedby = moves + 21;
    nodes[542].reachedby = moves + 22;
    nodes[543].reachedby = moves + 42;
    nodes[544].reachedby = moves + 40;
    nodes[545].reachedby = moves + 35;
    nodes[546].reachedby = moves + 45;
    nodes[547].reachedby = moves + 46;
    nodes[548].reachedby = moves + 21;
    nodes[549].reachedby = moves + 22;
    nodes[550].reachedby = moves + 46;
    nodes[551].reachedby = moves + 44;
    nodes[552].reachedby = moves + 35;
    nodes[553].reachedby = moves + 49;
    nodes[554].reachedby = moves + 50;
    nodes[555].reachedby = moves + 21;
    nodes[556].reachedby = moves + 22;
    nodes[557].reachedby = moves + 50;
    nodes[558].reachedby = moves + 48;
    nodes[559].reachedby = moves + 35;
    isets[0].player = 0;
    isets[0].move0 = moves + 1;
    isets[0].nmoves = 2;
    isets[1].player = 0;
    isets[1].move0 = moves + 3;
    isets[1].nmoves = 2;
    isets[2].player = 0;
    isets[2].move0 = moves + 5;
    isets[2].nmoves = 3;
    isets[3].player = 0;
    isets[3].move0 = moves + 8;
    isets[3].nmoves = 3;
    isets[4].player = 0;
    isets[4].move0 = moves + 11;
    isets[4].nmoves = 1;
    isets[5].player = 0;
    isets[5].move0 = moves + 12;
    isets[5].nmoves = 1;
    isets[6].player = 0;
    isets[6].move0 = moves + 13;
    isets[6].nmoves = 2;
    isets[7].player = 0;
    isets[7].move0 = moves + 15;
    isets[7].nmoves = 3;
    isets[8].player = 0;
    isets[8].move0 = moves + 18;
    isets[8].nmoves = 3;
    isets[9].player = 0;
    isets[9].move0 = moves + 21;
    isets[9].nmoves = 2;
    isets[10].player = 0;
    isets[10].move0 = moves + 23;
    isets[10].nmoves = 2;
    isets[11].player = 1;
    isets[11].move0 = moves + 26;
    isets[11].nmoves = 2;
    isets[12].player = 1;
    isets[12].move0 = moves + 28;
    isets[12].nmoves = 2;
    isets[13].player = 1;
    isets[13].move0 = moves + 30;
    isets[13].nmoves = 2;
    isets[14].player = 1;
    isets[14].move0 = moves + 32;
    isets[14].nmoves = 2;
    isets[15].player = 1;
    isets[15].move0 = moves + 34;
    isets[15].nmoves = 2;
    isets[16].player = 1;
    isets[16].move0 = moves + 36;
    isets[16].nmoves = 2;
    isets[17].player = 2;
    isets[17].move0 = moves + 39;
    isets[17].nmoves = 2;
    isets[18].player = 2;
    isets[18].move0 = moves + 41;
    isets[18].nmoves = 2;
    isets[19].player = 2;
    isets[19].move0 = moves + 43;
    isets[19].nmoves = 2;
    isets[20].player = 2;
    isets[20].move0 = moves + 45;
    isets[20].nmoves = 2;
    isets[21].player = 2;
    isets[21].move0 = moves + 47;
    isets[21].nmoves = 2;
    isets[22].player = 2;
    isets[22].move0 = moves + 49;
    isets[22].nmoves = 2;
    // move 0 is empty sequence for player 0
    moves[1].atiset = isets + 0;
    moves[1].behavprob.num = 0;
    moves[1].behavprob.den = 1;
    moves[2].atiset = isets + 0;
    moves[2].behavprob.num = 0;
    moves[2].behavprob.den = 1;
    moves[3].atiset = isets + 1;
    moves[3].behavprob.num = 0;
    moves[3].behavprob.den = 1;
    moves[4].atiset = isets + 1;
    moves[4].behavprob.num = 0;
    moves[4].behavprob.den = 1;
    moves[5].atiset = isets + 2;
    moves[5].behavprob.num = 0;
    moves[5].behavprob.den = 1;
    moves[6].atiset = isets + 2;
    moves[6].behavprob.num = 0;
    moves[6].behavprob.den = 1;
    moves[7].atiset = isets + 2;
    moves[7].behavprob.num = 0;
    moves[7].behavprob.den = 1;
    moves[8].atiset = isets + 3;
    moves[8].behavprob.num = 0;
    moves[8].behavprob.den = 1;
    moves[9].atiset = isets + 3;
    moves[9].behavprob.num = 0;
    moves[9].behavprob.den = 1;
    moves[10].atiset = isets + 3;
    moves[10].behavprob.num = 0;
    moves[10].behavprob.den = 1;
    moves[11].atiset = isets + 4;
    moves[11].behavprob.num = 1;
    moves[11].behavprob.den = 1;
    moves[12].atiset = isets + 5;
    moves[12].behavprob.num = 1;
    moves[12].behavprob.den = 1;
    moves[13].atiset = isets + 6;
    moves[13].behavprob.num = 0;
    moves[13].behavprob.den = 1;
    moves[14].atiset = isets + 6;
    moves[14].behavprob.num = 0;
    moves[14].behavprob.den = 1;
    moves[15].atiset = isets + 7;
    moves[15].behavprob.num = 0;
    moves[15].behavprob.den = 1;
    moves[16].atiset = isets + 7;
    moves[16].behavprob.num = 0;
    moves[16].behavprob.den = 1;
    moves[17].atiset = isets + 7;
    moves[17].behavprob.num = 0;
    moves[17].behavprob.den = 1;
    moves[18].atiset = isets + 8;
    moves[18].behavprob.num = 0;
    moves[18].behavprob.den = 1;
    moves[19].atiset = isets + 8;
    moves[19].behavprob.num = 0;
    moves[19].behavprob.den = 1;
    moves[20].atiset = isets + 8;
    moves[20].behavprob.num = 0;
    moves[20].behavprob.den = 1;
    moves[21].atiset = isets + 9;
    moves[21].behavprob.num = 0;
    moves[21].behavprob.den = 1;
    moves[22].atiset = isets + 9;
    moves[22].behavprob.num = 0;
    moves[22].behavprob.den = 1;
    moves[23].atiset = isets + 10;
    moves[23].behavprob.num = 0;
    moves[23].behavprob.den = 1;
    moves[24].atiset = isets + 10;
    moves[24].behavprob.num = 0;
    moves[24].behavprob.den = 1;
    // move 25 is empty sequence for player 1
    moves[26].atiset = isets + 11;
    moves[27].atiset = isets + 11;
    moves[28].atiset = isets + 12;
    moves[29].atiset = isets + 12;
    moves[30].atiset = isets + 13;
    moves[31].atiset = isets + 13;
    moves[32].atiset = isets + 14;
    moves[33].atiset = isets + 14;
    moves[34].atiset = isets + 15;
    moves[35].atiset = isets + 15;
    moves[36].atiset = isets + 16;
    moves[37].atiset = isets + 16;
    // move 38 is empty sequence for player 2
    moves[39].atiset = isets + 17;
    moves[40].atiset = isets + 17;
    moves[41].atiset = isets + 18;
    moves[42].atiset = isets + 18;
    moves[43].atiset = isets + 19;
    moves[44].atiset = isets + 19;
    moves[45].atiset = isets + 20;
    moves[46].atiset = isets + 20;
    moves[47].atiset = isets + 21;
    moves[48].atiset = isets + 21;
    moves[49].atiset = isets + 22;
    moves[50].atiset = isets + 22;

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

