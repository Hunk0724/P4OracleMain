/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Obtencion de estadisticas para el calculo de caracteristicas del DataSet %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% CICIDS-2017 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%% UdeA/Colombia - UFRGS/Brasil %%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%% By: Sebastian Gomez Macias %%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%% Asesor: Juan Felipe Botero Vega %%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%% CoAsesor: Luciano Paschoal Gaspary %%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/

#include <core.p4>
#include <v1model.p4>

#include "include/header.p4"
#include "include/parser.p4"
#include "include/checksum.p4"

#define CPU_CLONE_SESSION_ID 99
//I use it for tests, see what I am sending to the controller, sending it through port 2 of the sw and capture it in wireshark
#define PORT_CLONE_SESSION_ID 69
#define CPU_PORT 255

#define WindowDuration 40000000 //20 seconds in microsecond
#define NumFlows 800000
//#define NumFlows 20

#define FIN 1           //000001
#define SYN 2           //000010
#define RST 4           //000100
#define PSH 8           //001000
#define ACK 16          //010000
#define FIN_ACK 17      //010001
#define SYN_ACK 18      //010010
#define RST_ACK 20      //010100
#define PSH_ACK 24      //011000
#define URG 32          //100000
#define URG_ACK 48      //110000
#define ECE 64          //1000000
#define CWR 128         //10000000

//Values that metadata can have instance_type and
//Their respective interpretations
const bit<32> NORMAL = 0;
const bit<32> CLONE1 = 1; //Cloned package from ingress to egress
const bit<32> CLONE2 = 2; //Cloned package from egress to egress
const bit<32> RECIRCULATED = 4; 
const bit<32> RESUBMIT = 6;
const bit<16> CustomEtherType = 0x6969; //En DEC: 26985
const bit<2> right_lane = 0; // Right lane
const bit<2> left_lane = 1; // Left lane

const bit<2> DDoS_Tag = 3;
const bit<2> Benign_Tag = 0; 

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control c_ingress(inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t standard_metadata) {

    //----------------- Define registers -------------------------------------- 

    //--- Counters of types of packets arriving at the switch
    register <bit<32>> (1) NumPacketsUDP;
    register <bit<32>> (1) NumPacketsTCP;
    //--- Timestamp of the first packet in the flow (milliseconds)
    register <bit<48>> (NumFlows) InitTimeFlow;
    //--- Timestamp of the last packet that arrived at the switch (milliseconds)
    register <bit<48>> (NumFlows) LastTimePacket;
    //--- Flow state (0,1 or 2)
    register <bit<2>> (NumFlows) FlowState;
    //--- Byte and packet statistics
    register <bit<32>> (NumFlows) TotPkts;
    register <bit<32>> (NumFlows) TotLenPkts;
    register <bit<32>> (NumFlows) PktLenMin;
    register <bit<32>> (NumFlows) PktLenMax;
    register <bit<40>> (NumFlows) TotLenSquare;
    register <bit<48>> (NumFlows) TotIAT;
    register <bit<56>> (NumFlows) TotIATsquare;
    //--- Registrars that manage the flow collection window and the sending of these
    register <bit<32>> (NumFlows) indexsFWD0;
    register <bit<32>> (NumFlows) indexsBWD0;
    register <bit<32>> (NumFlows) indexsFWD1;
    register <bit<32>> (NumFlows) indexsBWD1;
    register <bit<32>> (2) ContIndexs;
    register <bit<48>> (1) InitTimeWindow;
    register <bit<16>> (1) WindowId;
    register <bit<2>> (1) Carril; //Lane
    register <bit<16>> (1) colitions;
    //--- flow label
    register <bit<1>> (NumFlows) tag;
    //register <bit<48>> (1) test;

    //------------------------------- Mis Actions --------------------------------------------

    action calculate_hash() {
        hash(meta.index, 
            HashAlgorithm.crc32,
            (bit<32>) 0,
            {hdr.ipv4.src_addr,hdr.ipv4.dst_addr,meta.srcP,meta.dstP,hdr.ipv4.protocol}, 
            (bit<32>) NumFlows - 1
        );
        hash(meta.index2, 
            HashAlgorithm.crc32, 
            (bit<32>) 0, 
            {hdr.ipv4.dst_addr,hdr.ipv4.src_addr,meta.dstP,meta.srcP,hdr.ipv4.protocol}, 
            (bit<32>) NumFlows - 1
        );
    }

    action SaveIntoMetas() {
        //--- Statistics in FWD
        InitTimeFlow.read(meta.InitTimeFlowM, meta.indF);
        LastTimePacket.read(meta.LastTimePacketM, meta.indF);
        TotPkts.read(meta.TotPktsM, meta.indF);
        TotLenPkts.read(meta.TotLenPktsM, meta.indF);
        //--- Statistics in BWD
        InitTimeFlow.read(meta.InitTimeFlowM2, meta.indB);
        LastTimePacket.read(meta.LastTimePacketM2, meta.indB);
        TotPkts.read(meta.TotPktsM2, meta.indB);
        TotLenPkts.read(meta.TotLenPktsM2, meta.indB);
        TotLenSquare.read(meta.TotLenSquareM2, meta.indB);
        //--- Direction independent statistics
        TotIAT.read(meta.TotIATM, meta.indF);
        TotIATsquare.read(meta.TotIATsquareM, meta.indF);
        tag.read(meta.tagM,meta.indF);
        //--- control information
        WindowId.read(meta.WindowNumM, 0);

        if (meta.LastTimePacketM > meta.LastTimePacketM2) {
            meta.FlowDurationM = meta.LastTimePacketM - meta.InitTimeFlowM;
        } else {
            meta.FlowDurationM = meta.LastTimePacketM2 - meta.InitTimeFlowM;
        }
    }

    action zerar(){
        //--- the subflow registers FWD and BWD are reset to zero.
        FlowState.write(meta.indF, 0);
        FlowState.write(meta.indB, 0);
        InitTimeFlow.write(meta.indF, 0);
        InitTimeFlow.write(meta.indB, 0);
        tag.write(meta.indF,0);
        LastTimePacket.write(meta.indF, 0);
        LastTimePacket.write(meta.indB, 0);
        /*TotPkts.write(meta.indF, 0);
        TotPkts.write(meta.indB, 0);
        TotLenPkts.write(meta.indF, 0);
        TotLenPkts.write(meta.indB, 0);
        PktLenMin.write(meta.indF, 0);
        PktLenMin.write(meta.indB, 0);
        PktLenMax.write(meta.indF, 0);
        PktLenMax.write(meta.indB, 0);*/
    }

    action GetindexsFWD1(bit<32> conter){
        // The FWD and BWD index of the flow that is being targeted by "conter" of the Left lane is obtained.
        indexsFWD1.read(meta.indF,conter - 1);
        indexsBWD1.read(meta.indB,conter - 1);
    }

    action GetindexsFWD0(bit<32> conter){
        // The FWD and BWD index of the flow that is being pointed by "conter" of the Right lane is obtained. 
        indexsFWD0.read(meta.indF,conter - 1);
        indexsBWD0.read(meta.indB,conter - 1);
    }

    // funcion send para vaciar lo recolectado previamente en el carril Derecho
    action send_D(bit<32> conter){
        meta.NumFlowsByPacket = 1;
        GetindexsFWD0(conter);
        // se guarda la informacion del flujo en las metadatas
        SaveIntoMetas();
        // se concatena todas las estadisticas del flujo
        meta.Flow1 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        // se cera la informacion del flujo de los registradores de estadisticas.
        zerar();
    }

    // send function to empty the previously collected in the left lane
    action send_I(bit<32> conter){
        meta.NumFlowsByPacket = 1;
        GetindexsFWD1(conter);        
        // The information of the flow in metadata is saved
        SaveIntoMetas();
        // all flow statistics are concatenated
        meta.Flow1 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        // se cera la informacion del flujo de los registradores de estadisticas.
        zerar();
    }

    action send_x5_D(bit<32> conter){
        meta.NumFlowsByPacket = 5;
        GetindexsFWD0(conter);
        SaveIntoMetas();
        meta.Flow1 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD0(conter-1);
        SaveIntoMetas();
        meta.Flow2 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD0(conter-2);
        SaveIntoMetas();
        meta.Flow3 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD0(conter-3);
        SaveIntoMetas();
        meta.Flow4 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD0(conter-4);
        SaveIntoMetas();
        meta.Flow5 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
    }

    action send_x5_I(bit<32> conter){
        meta.NumFlowsByPacket = 5;
        GetindexsFWD1(conter);
        SaveIntoMetas();
        meta.Flow1 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD1(conter-1);
        SaveIntoMetas();
        meta.Flow2 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD1(conter-2);
        SaveIntoMetas();
        meta.Flow3 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD1(conter-3);
        SaveIntoMetas();
        meta.Flow4 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD1(conter-4);
        SaveIntoMetas();
        meta.Flow5 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
    }

    action send_x10_D(bit<32> conter){
        send_x5_D(conter);

        meta.NumFlowsByPacket = 10;
        GetindexsFWD0(conter-5);
        SaveIntoMetas();
        meta.Flow6 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD0(conter-6);
        SaveIntoMetas();
        meta.Flow7 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD0(conter-7);
        SaveIntoMetas();
        meta.Flow8 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD0(conter-8);
        SaveIntoMetas();
        meta.Flow9 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD0(conter-9);
        SaveIntoMetas();
        meta.Flow10 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
    }

    action send_x10_I(bit<32> conter){
        send_x5_I(conter);

        meta.NumFlowsByPacket = 10;
        GetindexsFWD1(conter-5);
        SaveIntoMetas();
        meta.Flow6 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD1(conter-6);
        SaveIntoMetas();
        meta.Flow7 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD1(conter-7);
        SaveIntoMetas();
        meta.Flow8 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD1(conter-8);
        SaveIntoMetas();
        meta.Flow9 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
        //----------------------
        GetindexsFWD1(conter-9);
        SaveIntoMetas();
        meta.Flow10 = meta.FlowDurationM ++ meta.TotPktsM ++ meta.TotPktsM2 ++ meta.TotLenPktsM ++ meta.TotLenPktsM2 ++ 
                    meta.TotLenSquareM2 ++ meta.TotIATM ++ meta.TotIATsquareM ++ meta.WindowNumM ++ (bit<8>)meta.tagM;
        zerar();
    }


    action clone_to_cpu() {
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, 
            {standard_metadata.instance_type, standard_metadata.ingress_port,
                meta.NumFlowsByPacket,
                meta.Flow1,
                meta.Flow2,
                meta.Flow3,
                meta.Flow4,
                meta.Flow5,
                meta.Flow6,
                meta.Flow7,
                meta.Flow8,
                meta.Flow9,
                meta.Flow10
            });
    }


    //-------------------------- Own the Template ------------------------------------------

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        // Packets sent to the controller needs to be prepended with the
        // packet-in header. By setting it valid we make sure it will be
        // deparsed on the wire (see c_deparser).
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }
    action set_out_port(bit<9> port) {
        // Specifies the output port for this packet by setting the
        // corresponding metadata.
        standard_metadata.egress_spec = port;
    }
    action _drop() {
        //mark_to_drop(standard_metadata);
	mark_to_drop();
    }

    table t_l2_fwd {
        key = {
            standard_metadata.ingress_port  : ternary;
            hdr.ethernet.dst_addr           : ternary;
            hdr.ethernet.src_addr           : ternary;
            hdr.ethernet.ether_type         : ternary;
        }
        actions = {
            set_out_port;
            send_to_cpu;
            _drop;
            NoAction;
        }
        default_action = NoAction();
    }

    //---------------------------------------------------------------------------------------

    apply {
        bit<48> InitWin;
        InitTimeWindow.read(InitWin,0);
        //--- I am initialized the initial window time.
        // It will only be entered once in all the life of the program and will be in the first package of all
        if (InitWin == 0) {
            InitWin = standard_metadata.ingress_global_timestamp;
            InitTimeWindow.write(0,InitWin);
        }

        // ###################################################################################################################
        // ############################### Lane Management Module and time window ##################################
        // ###################################################################################################################
        bit<2> carril; 
        Carril.read(carril,0); //carril = Carril[0] 
        bit<32> cont; //It saves me the number of flows stored so far in the lane needed.
            
        if (carril == right_lane) //lane == right
        {
            ContIndexs.read(cont,(bit<32>)left_lane); //cont = ContIndexs[1]

            // It validates if the window is still active. if it is not, a lane change is made
            // idle window
            if (( standard_metadata.ingress_global_timestamp - InitWin) >= WindowDuration) {
                // It continues sending the statistics if the window ends and it has not finished sending the statistics yet.
                // nothing is missing to send, we proceed to change lanes.
                if (cont == 0) {
                    //lane change
                    Carril.write(0,left_lane); //Carril[0] = left_lane
                    // The time window is reset by assigning the current timestamp 
                    InitTimeWindow.write(0,standard_metadata.ingress_global_timestamp); //InitTimeWindow[0] = standard_metadata.ingress_global_timestamp
                    // The window ID is increased by 1
                    WindowId.read(meta.WindowNumM, 0); //meta.WindowNumM = WindowId[0]
                    WindowId.write(0,meta.WindowNumM + 1); //WindowId[0] = meta.WindowNumM + 1
                
                // Missing statistics to send, they continue to be sent.
                } else {
                    // It will store the statistics of the flow in the metadas that will be kept together with the cloned package below
                    //send_I(cont);
                    //cont = cont - 1;
                    if (cont >= 10) {
                        send_x10_I(cont);
                        cont = cont - 10;
                    } else if (cont >= 5) {
                        send_x5_I(cont);
                        cont = cont - 5;
                    } else {
                        send_I(cont);
                        cont = cont - 1;
                    }
                    
                    clone_to_cpu();
                    //------------------------------------------
                    
                    ContIndexs.write((bit<32>)left_lane, cont); //ContIndexs[1] = cont

                    // After decreasing the left accountant, we validated if in the next occasion there would be more flows to send,
                    // Case does not have more flows to send, we proceed to change lane and update the window.
                    if (cont == 0) {
                        //Lane change
                        Carril.write(0,left_lane);
                        // The time window is reset by assigning the current timestamp
                        InitTimeWindow.write(0,standard_metadata.ingress_global_timestamp);
                        // the window ID is incremented by 1
                        WindowId.read(meta.WindowNumM, 0);
                        WindowId.write(0,meta.WindowNumM + 1);
                    }

                }               

            // active window
            } else {
                // If you enter, there are still statistics from the previous window to send to the controller.
                if (cont != 0) {
                    //send_I(cont);
                    //cont = cont - 1;
                    if (cont >= 10) {
                        send_x10_I(cont);
                        cont = cont - 10;
                    } else if (cont >= 5) {
                        send_x5_I(cont);
                        cont = cont - 5;
                    } else {
                        send_I(cont);
                        cont = cont - 1;
                    }

                    clone_to_cpu();
                    
                    //------------------------------------------
                    // We decrease in 1 the counter after cloning the package that will be sent to the controller
                    ContIndexs.write((bit<32>)left_lane, cont);
                }
            }


        // carril == left_lane 左
        } else {
            ContIndexs.read(cont,(bit<32>)right_lane);

            // me valida si la ventana aun esta activa. si no lo está, se hace cambio de carril
            // ventana inactiva
            if (( standard_metadata.ingress_global_timestamp - InitWin) >= WindowDuration) {
                // se continua enviando las estadisticas así la ventana haya expirado
                // no falta nada para enviar, se procede al cambio de carril.
                if (cont == 0) { 
                    //cambio de carril
                    Carril.write(0,right_lane);
                    // se reinicia la ventana de tiempo asignando el actual timestamp 
                    InitTimeWindow.write(0,standard_metadata.ingress_global_timestamp);
                    // se incrementa en 1 el ID de la ventana
                    WindowId.read(meta.WindowNumM, 0);
                    WindowId.write(0,meta.WindowNumM + 1);

                // Falta estadisticas por enviar, se continuan enviando.
                } else {
                    // Nos almacenará la estadisticas del flujo en las metadas que se conservaran junto con el paquete clonado a continuacion
                    //send_D(cont);
                    //cont = cont - 1;
                    if (cont >= 10) {
                        send_x10_D(cont);
                        cont = cont - 10;
                    } else if (cont >= 5) {
                        send_x5_D(cont);
                        cont = cont - 5;
                    } else {
                        send_D(cont);
                        cont = cont - 1;
                    }

                    clone_to_cpu();

                    //------------------------------------------
                    // decrementamos en 1 el contador despues de clonar el paquete que sera enviado al controlador
                    ContIndexs.write((bit<32>)right_lane, cont);

                    // despues de decrementar el contador derecho, validamos si en la proxima ocasion habria mas flujos para enviar,
                    // caso no tenga mas flujos para enviar, se procede a cambiar de carril y actualizar la ventana.
                    if (cont == 0) { 
                        //cambio de carril
                        Carril.write(0,right_lane);
                        // se reinicia la ventana de tiempo asignando el actual timestamp 
                        InitTimeWindow.write(0,standard_metadata.ingress_global_timestamp);
                        // se incrementa en 1 el ID de la ventana
                        WindowId.read(meta.WindowNumM, 0);
                        WindowId.write(0,meta.WindowNumM + 1);
                    }
                }


            // ventana activa
            } else {
                // si entra, hay aun estadisticas de la anterior ventana para enviar al controlador.
                if (cont != 0) {
                    //send_D(cont);
                    //cont = cont - 1;
                    if (cont >= 10) {
                        send_x10_D(cont);
                        cont = cont - 10;
                    } else if (cont >= 5) {
                        send_x5_D(cont);
                        cont = cont - 5;
                    } else {
                        send_D(cont);
                        cont = cont - 1;
                    }

                    clone_to_cpu();

                    //------------------------------------------
                    // decrementamos en 1 el contador despues de clonar el paquete que sera enviado al controlador
                    ContIndexs.write((bit<32>)right_lane, cont);
                }
            }

        }
        // ###################################################################################################################

        //$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
        //$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ Statistics module $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
        //$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

        // the current packet is sampled if it is UDP or TCP.
        if (hdr.tcp.isValid() || hdr.udp.isValid()){
            //the index belonging to the flow to which the packet belongs is calculated
            calculate_hash(); 
            FlowState.read(meta.state,meta.index); //meta.state = FlowState[meta.index] ;
            FlowState.read(meta.state2,meta.index2); //meta.state2 = FlowState[meta.index2] ;
            //state = 0 means that the flow is new and has not yet been sampled
            
            //--- It is a new flow and the position in each register is at zero.
            //--- Both downstream FWD and BWD are in progress.
            if (meta.state == 0 && meta.state2 == 0) {
                //the TimeStamp of the first packet of the flow is instantiated
                InitTimeFlow.write(meta.index, standard_metadata.ingress_global_timestamp); //InitTimeFlow[meta.index] = standard_metadata.ingress_global_timestamp;
                //---- the initial value of all registers is instantiated----------------------------------------------
                LastTimePacket.write(meta.index, standard_metadata.ingress_global_timestamp); //LastTimePacket[meta.index] = standard_metadata.ingress_global_timestamp;
                // if initialized with 1 of the total number of packets of the downstream
                TotPkts.write(meta.index, 1); //TotPkts[meta.index] = 1;

                bit<32> payload;
                if (hdr.tcp.isValid()) { //NumPackets、TotLenPkts、PktLenMin、PktLenMax
                    //---- It tells me the number of TCP packets that go through the sw
                    NumPacketsTCP.read(meta.contador,0);        
                    NumPacketsTCP.write(0,meta.contador + 1); //NumPacketsTCP[0] = NumPacketsTCP[0] + 1;

                    // we store the length in bytes of the TCP segment data (payload)
                    // payload = LenPacketIP - ipv4Header - TCPheader
                    payload = (bit<32>)hdr.ipv4.len - ((bit<32>)hdr.ipv4.ihl * 4) - ((bit<32>)hdr.tcp.data_offset * 4);
                    TotLenPkts.write(meta.index, payload); //TotLenPkts[meta.index] = payload;

                    //the min and max length are initialized with the current packet size as a reference value
                    PktLenMin.write(meta.index, payload); //PktLenMin[meta.index] = payload;
                    PktLenMax.write(meta.index, payload); //PktLenMax[meta.index] = payload;

                } else {
                    NumPacketsUDP.read(meta.contador,0);                
                    NumPacketsUDP.write(0,meta.contador + 1); //NumPacketsUDP[0] = NumPacketsUDP[0] + 1;

                    // We save the length in bytes of the data of the UDP Datagram (payload)
                    // payload = LenDatagramaUDP - UDPheader
                    payload = (bit<32>)(hdr.udp.len - 8);
                    TotLenPkts.write(meta.index, payload);

                    //the min and max length are initialized with the current packet size as a reference value
                    PktLenMin.write(meta.index, payload);
                    PktLenMax.write(meta.index, payload);
                }
                // TotLenSquare
                // The square of the length of the package is saved (payload ^ 2)
                TotLenSquare.write(meta.index, (bit<40>)payload * (bit<40>)payload );

                //TotIAT
                // temporary statistics. arrival time between packets of a flow regardless of its direction.
                TotIAT.write(meta.index, 0); //TotIAT[meta.index] = 0;
                TotIATsquare.write(meta.index,0); //TotIATsquare[meta.index] = 0;

                //############################## Save Indexes #################################
                Carril.read(carril,0);
                if (carril == right_lane){
                    ContIndexs.read(cont,(bit<32>)right_lane);
                    // We keep the index of the new flow in the right lane
                    indexsFWD0.write(cont,meta.index);
                    indexsBWD0.write(cont,meta.index2);
                    // the ContIndexs counter is incremented
                    ContIndexs.write((bit<32>)right_lane,cont + 1); //ContIndexs[right_lane] = ContIndex[right_lane] + 1;
                } else {
                    ContIndexs.read(cont,(bit<32>)left_lane);
                    // Guardamos los index del nuevo flujo en el carril derecho
                    indexsFWD1.write(cont,meta.index);
                    indexsBWD1.write(cont,meta.index2);
                    // se incrementa el contador ContIndexs
                    ContIndexs.write((bit<32>)left_lane,cont + 1);
                }               
                //###################################################################################

                //the FWD flow state is changed to 1, that is, active flow             
                FlowState.write(meta.index, 1);

            
            //--- The flow exists and proceeds to be updated
            //--- (FWD) || (BWD)
            } else if ((meta.state == 1 && meta.state2 == 0) || (meta.state == 0 && meta.state2 == 1)) {

                InitTimeFlow.read(meta.InitTimeFlowM,meta.index); //meta.InitTimeFlowM = InitTimeFlow[meta.index];
                LastTimePacket.read(meta.LastTimePacketM, meta.index); //meta.LastTimePacketM = LastTimePacket[meta.index];
                LastTimePacket.read(meta.LastTimePacketM2, meta.index2); //meta.LastTimePacketM2 = LastTimePacket[meta.index2];

                // I identify the return subflow BWD which has not yet been initiated and proceeds then.
                // The code is recycled
                if (meta.InitTimeFlowM == 0 && meta.state == 0){
                    //the TimeStamp of the first packet in the flow is instantiated
                    InitTimeFlow.write(meta.index, standard_metadata.ingress_global_timestamp);
                    LastTimePacket.write(meta.index, standard_metadata.ingress_global_timestamp);
                    TotPkts.write(meta.index, 1);

                    bit<32> payload;
                    if (hdr.tcp.isValid()) {
                        NumPacketsTCP.read(meta.contador,0);                
                        NumPacketsTCP.write(0,meta.contador + 1);

                        payload = (bit<32>)hdr.ipv4.len - ((bit<32>)hdr.ipv4.ihl * 4) - ((bit<32>)hdr.tcp.data_offset * 4);
                        TotLenPkts.write(meta.index, payload);

                        PktLenMin.write(meta.index, payload);
                        PktLenMax.write(meta.index, payload);

                    } else {
                        NumPacketsUDP.read(meta.contador,0);                
                        NumPacketsUDP.write(0,meta.contador + 1);

                        payload = (bit<32>)(hdr.udp.len - 8);
                        TotLenPkts.write(meta.index, payload);

                        PktLenMin.write(meta.index, payload);
                        PktLenMax.write(meta.index, payload);
                    }

                    TotLenSquare.write(meta.index, (bit<40>)payload * (bit<40>)payload );

                // I update the subluxury FWD or BWD which are already initialized.
                } else {
                    // --- Loading data into metadata                  
                    TotPkts.read(meta.TotPktsM, meta.index);
                    TotLenPkts.read(meta.TotLenPktsM, meta.index);
                    PktLenMin.read(meta.PktLenMinM, meta.index);
                    PktLenMax.read(meta.PktLenMaxM, meta.index);
                    TotLenSquare.read(meta.TotLenSquareM, meta.index);

                    // --- One more packet is added to the subflow
                    TotPkts.write(meta.index, meta.TotPktsM + 1);

                    //--------------------------------------------------------------
                    bit<32> payload;
                    // --- tcp
                    if (hdr.tcp.isValid()) {
                        NumPacketsTCP.read(meta.contador,0);                
                        NumPacketsTCP.write(0,meta.contador + 1);

                        // we save the length in bytes of the TCP segment data (payload)
                        // payload = LenPacketIP - ipv4Header - TCPheader
                        payload = (bit<32>)hdr.ipv4.len - ((bit<32>)hdr.ipv4.ihl * 4) - ((bit<32>)hdr.tcp.data_offset * 4);
                        //Add the length of the payoad to the aggregate
                        TotLenPkts.write(meta.index, meta.TotLenPktsM + payload);                  

                    // --- udp
                    } else {
                        NumPacketsUDP.read(meta.contador,0);                
                        NumPacketsUDP.write(0,meta.contador + 1);

                        // We use the length in bytes of the UDP datagram data (payload)
                        // payload = LenDatagramaUDP - UDPheader
                        payload = (bit<32>)(hdr.udp.len - 8);
                        //Se suma la longitud del payoad al agregado
                        TotLenPkts.write(meta.index, meta.TotLenPktsM + payload);
                    }
                    //--------------------------------------------------------------

                    //Update the minimum length value
                    if (payload < meta.PktLenMinM){
                        PktLenMin.write(meta.index, payload);
                    }
                    //Update the maximum length value
                    if (payload > meta.PktLenMaxM){
                        PktLenMax.write(meta.index, payload);
                    }

                    // The square of the packet length is added (payload^2)
                    TotLenSquare.write(meta.index, meta.TotLenSquareM + ((bit<40>)payload * (bit<40>)payload) );

                    //The arrival time of the last package is updated with the arrival time of the current package. 
                    LastTimePacket.write(meta.index, standard_metadata.ingress_global_timestamp);
                }

                // ¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡ Calculation of Statistics regardless of its direction ¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡
                //--- This if tells me if the last packet of the flow was in the FWD or BWD direction
                if (meta.LastTimePacketM > meta.LastTimePacketM2) {
                    bit<48> IAT = standard_metadata.ingress_global_timestamp - meta.LastTimePacketM;
                    // ---It identifies me which is the index that points to the FWD address. the statistics that are
                    // Regardless of the address, they will be stored in the index that points to FWD.
                    if (meta.state == 1) {
                        TotIAT.read(meta.TotIATM, meta.index);
                        TotIAT.write(meta.index, meta.TotIATM + IAT);
                        TotIATsquare.read(meta.TotIATsquareM, meta.index);
                        TotIATsquare.write(meta.index, meta.TotIATsquareM + ((bit<56>)IAT * (bit<56>)IAT) );
                    } else {
                        TotIAT.read(meta.TotIATM, meta.index2);
                        TotIAT.write(meta.index2, meta.TotIATM + IAT);
                        TotIATsquare.read(meta.TotIATsquareM, meta.index2);
                        TotIATsquare.read(meta.TotIATsquareM, meta.index2);
                        TotIATsquare.write(meta.index2, meta.TotIATsquareM + ((bit<56>)IAT * (bit<56>)IAT) );
                    }
                    
                } else {
                    bit<48> IAT = standard_metadata.ingress_global_timestamp - meta.LastTimePacketM2;
                    if (meta.state == 1) {
                        TotIAT.read(meta.TotIATM, meta.index);
                        TotIAT.write(meta.index, meta.TotIATM + IAT);
                        TotIATsquare.read(meta.TotIATsquareM, meta.index);
                        TotIATsquare.write(meta.index, meta.TotIATsquareM + ((bit<56>)IAT * (bit<56>)IAT) );
                    } else {
                        TotIAT.read(meta.TotIATM, meta.index2);
                        TotIAT.write(meta.index2, meta.TotIATM + IAT);
                        TotIATsquare.read(meta.TotIATsquareM, meta.index2);
                        TotIATsquare.write(meta.index2, meta.TotIATsquareM + ((bit<56>)IAT * (bit<56>)IAT) );
                    }

                }
                
                //--- Check and update the flow label. 0:Benign, 1:DDoS

                bit<1> T;
                // we read the array tag in the FWD index.
                if (meta.state == 1){
                    tag.read(T, meta.index);
                    if (T == 0) {
                        if (hdr.ipv4.tag == DDoS_Tag) {
                            tag.write(meta.index, 1);
                        }
                    }
                } else {
                    tag.read(T, meta.index2);
                    if (T == 0) {
                        if (hdr.ipv4.tag == DDoS_Tag) {
                            tag.write(meta.index2, 1);
                        }
                    }
                }
                
                // ¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡¡

            // Enter if state == 1 and state2 == 1, this state does not exist, which translates into a collision case
            } else {
                bit<16> col;
                colitions.read(col,0);
                colitions.write(0,col + 1);
            }

        }
        
        //$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
    

        if (standard_metadata.ingress_port == CPU_PORT) {
            // Packet received from CPU_PORT, this is a packet-out sent by the
            // controller. Skip table processing, set the egress port as
            // requested by the controller (packet_out header) and remove the
            // packet_out header.
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
        } else {
            // Packet received from data plane port.
            // Applies table t_l2_fwd to the packet.            
            if (t_l2_fwd.apply().hit) {
                // Packet hit an entry in t_l2_fwd table. A forwarding action
                // has already been taken. No need to apply other tables, exit
                // this control block.
                return;
            } else {
                //--- Definir puerto de salida de manera estatico -------------------------------------
                standard_metadata.egress_spec = 2;
            }
        }
        
     }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control c_egress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {

    //register <bit<48>> (1) test2;

    apply {

        if (standard_metadata.instance_type == CLONE1) {
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = standard_metadata.ingress_port;
            hdr.ethernet.ether_type = CustomEtherType; //se usa un valor de EtherType propio para filtrar

            if (meta.NumFlowsByPacket == 1) {
                hdr.flow.setValid();
                hdr.flow.NumFlowsByPacket = meta.NumFlowsByPacket;
                hdr.flow.F1 = meta.Flow1;

                // se quita el payload del paquete solo indicando el numero de bytes que se quieren transmitir (truncar)
                // packet_in (2 bytes) + ethernet (14 bytes) + flow (44 bytes)  = 60 bytes         
                truncate(60);
            } else if (meta.NumFlowsByPacket == 5) {
                hdr.flow_x5.setValid();
                hdr.flow_x5.NumFlowsByPacket = meta.NumFlowsByPacket;
                hdr.flow_x5.F1 = meta.Flow1;
                hdr.flow_x5.F2 = meta.Flow2;
                hdr.flow_x5.F3 = meta.Flow3;
                hdr.flow_x5.F4 = meta.Flow4;
                hdr.flow_x5.F5 = meta.Flow5;

                // packet_in (2 bytes) + ethernet (14 bytes) + flow_x5 (216 bytes)  = 232 bytes         
                truncate(232);
            } else if (meta.NumFlowsByPacket == 10) {
                hdr.flow_x10.setValid();
                hdr.flow_x10.NumFlowsByPacket = meta.NumFlowsByPacket;
                hdr.flow_x10.F1 = meta.Flow1;
                hdr.flow_x10.F2 = meta.Flow2;
                hdr.flow_x10.F3 = meta.Flow3;
                hdr.flow_x10.F4 = meta.Flow4;
                hdr.flow_x10.F5 = meta.Flow5;
                hdr.flow_x10.F6 = meta.Flow6;
                hdr.flow_x10.F7 = meta.Flow7;
                hdr.flow_x10.F8 = meta.Flow8;
                hdr.flow_x10.F9 = meta.Flow9;
                hdr.flow_x10.F10 = meta.Flow10;

                // packet_in (2 bytes) + ethernet (14 bytes) + flow_x10 (431 bytes)  = 447 bytes         
                truncate(447);    
                
            } else {
                return;
            }
            
            //Se retiran cabeceras que no se necesitan en el controlador.           
            hdr.ipv4.setInvalid();
            hdr.tcp.setInvalid();
            hdr.udp.setInvalid();
        }

    }
}

V1Switch(c_parser(),
         c_verify_checksum(),
         c_ingress(),
         c_egress(),
         c_compute_checksum(),
         c_deparser()) main;