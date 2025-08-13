# About

This file denotes the progress and state of the project.

# Currently missing Tables

- Attributes of each Layer
- Security Services, Levels etc. for each Layer

# References

<a id="1">[1]</a>: ZigBee Document 13-0402-13 Base Device Behavior Specification Version 1.0

<a id="2">[2]</a>: Zigbee Document 05-3474-23 Zigbee Specification Revision 23

<a id="3">[3]</a>: Zigbee Document 07-5123 Zigbee Cluster Library Specification Revision 8

<a id="4">[4]</a>: IEEE Std 802.15.4‐2015

# Legend

\- not applicable

❌ missing from ZBOSS

❓ present, unknown state

❗ present, known outdated or placeholder.

❎ present, tested working (may not be standard compliant)

✅ standard compliant, working.

# ZCL

## General Commands (ZCL[[3]](#3) 2.5)

|Command                                |Transmission   |Handling   |
|---------------------------------------|---------------|-----------|
|Read Attributes                        |❌             |❎         |
|Read Attributes Response               |❎             |❌         |
|Write Attributes                       |❌             |❎         |
|Write Attributes Undivided             |❌             |❌         |
|Write Attributes Response              |❎             |❌         |
|Write Attributes No Response           |❌             |❌         |
|Configure Reporting                    |❌             |❌         |
|Configure Reporting Response           |❌             |❌         |
|Read Reporting Configuration           |❌             |❌         |
|Read Reporting Configuration Response  |❌             |❌         |
|Report attributes                      |❌             |❌         |
|Default Response                       |❌             |❌         |
|Discover Attributes                    |❌             |❌         |
|Discover Attributes Response           |❌             |❌         |
|Read Attributes Structured             |❌             |❌         |
|Write Attributes Structured            |❌             |❌         |
|Write Attributes Structured response   |❌             |❌         |
|Discover Commands Received             |❌             |❌         |
|Discover Commands Received Response    |❌             |❌         |
|Discover Commands Generated            |❌             |❌         |
|Discover Commands Generated Response   |❌             |❌         |
|Discover Attributes Extended           |❌             |❌         |
|Discover Attributes Extended Response  |❌             |❌         |

## Clusters (ZCL[[3]](#3) 3-15)

Only listing the ones implemented/worked on.
|Cluster|Server Functions   |Server Attributes  |Client Functions   |Client Attributes  |
|-------|-------------------|-------------------|-------------------|-------------------|
|basic  |❌                 |❎                 |❌                 |-                  |
|groups |❎                 |❎                 |❌                 |-                  |
|on/off |❎                 |❎                 |❎                 |-                  |

# ZDP

## Client (Zigbee[[2]](#2) 2.4.3)

|Cluster                                    |Request Transmission   |Response handling  |
|-------------------------------------------|-----------------------|-------------------|
|NWK_addr_req                               |❓                     |❓                 |
|IEEE_addr_req                              |❓                     |❓                 |
|Node_Desc_req                              |❓                     |❓                 |
|Power_Desc_req                             |❓                     |❓                 |
|Simple_Desc_req                            |❓                     |❓                 |
|Active_EP_req                              |❓                     |❓                 |
|Match_Desc_req                             |❓                     |❓                 |
|Device_annce                               |❓                     |-                  |
|Parent_annce                               |❓                     |❌                 |
|System_Server_Discovery_req                |❓                     |❓                 |
|Bind_req                                   |❓                     |❓                 |
|Unbind_req                                 |❓                     |❓                 |
|Clear_All_Bindings_req                     |❌                     |❌                 |
|Mgmt_Lqi_req                               |❓                     |❓                 |
|Mgmt_Rtg_req                               |❌                     |❌                 |
|Mgmt_Bind_req                              |❌                     |❌                 |
|Mgmt_Leave_req                             |❓                     |❓                 |
|Mgmt_Permit_Joining_req                    |❓                     |❌                 |
|Mgmt_NWK_Update_req                        |❓                     |❓                 |
|Mgmt_NWK_Enhanced_Update_req               |❌                     |❌                 |
|Mgmt_NWK_IEEE_Joining_List_req             |❌                     |❌                 |
|Mgmt_NWK_Beacon_Survey_req                 |❌                     |❌                 |
|Security_Start_Key_Negotiation_req         |❌                     |❌                 |
|Security_Retrieve_Authentication_Token_req |❌                     |❌                 |
|Security_Get_Authentication_Level_req      |❌                     |❌                 |
|Security_Set_Configuration_req             |❌                     |❌                 |
|Security_Get_Configuration_req             |❌                     |❌                 |
|Security_Start_Key_Update_req              |❌                     |❌                 |
|Security_Decommission_req                  |❌                     |❌                 |
|Security_Challenge_req                     |❌                     |❌                 |
 
## Server (Zigbee[[2]](#2) 2.4.4)

|Cluster                                    |Request handling   |Response Transmission  |
|-------------------------------------------|-------------------|-----------------------|
|NWK_addr_rsp                               |❓                 |❓                     |
|IEEE_addr_rsp                              |❓                 |❓                     |
|Node_Desc_rsp                              |❓                 |❓                     |
|Power_Desc_rsp                             |❓                 |❓                     |
|Simple_Desc_rsp                            |❓                 |❓                     |
|Active_EP_rsp                              |❓                 |❓                     |
|Match_Desc_rsp                             |❎                 |❎                     |
|Parent_annce_rsp                           |❓                 |❓                     |
|System_Server_Discovery_rsp                |❓                 |❓                     |
|Bind_rsp                                   |❓                 |❓                     |
|Unbind_rsp                                 |❓                 |❓                     |
|Clear_All_Bindings_rsp                     |❌                 |❌                     |
|Mgmt_Lqi_rsp                               |❓                 |❓                     |
|Mgmt_Rtg_rsp                               |❌                 |❌                     |
|Mgmt_Bind_rsp                              |❌                 |❌                     |
|Mgmt_Leave_rsp                             |❓                 |❓                     |
|Mgmt_Permit_Joining_rsp                    |❌                 |❌                     |
|Mgmt_NWK_Update_notify                     |❓                 |❓                     |
|Mgmt_NWK_Enhanced_Update_notify            |❌                 |❌                     |
|Mgmt_NWK_IEEE_Joining_List_rsp             |❌                 |❌                     |
|Mgmt_NWK_Unsolicited_Enhanced_Update_notify|❌                 |❌                     |
|Mgmt_NWK_Beacon_Survey_rsp                 |❌                 |❌                     |
|Security_Start_Key_Negotiation_rsp         |❌                 |❌                     |
|Security_Retrieve_Authentication_Token_rsp |❌                 |❌                     |
|Security_Get_Authentication_Level_rsp      |❌                 |❌                     |
|Security_Set_Configuration_rsp             |❌                 |❌                     |
|Security_Get_Configuration_rsp             |❌                 |❌                     |
|Security_Start_Key_Update_rsp              |❌                 |❌                     |
|Security_Decommisioning_rsp                |❌                 |❌                     |
|Security_Challenge_rsp                     |❌                 |❌                     |

# APS

## Data Service (Zigbee[[2]](#2) 2.2.4.1)

|Primitive              |Request    |Confirm    |Indication |
|-----------------------|-----------|-----------|-----------|
|APSDE-DATA             |❎          |❓        |❎         |
|INTRP-DATA(Annex G)    |❎          |❌        |❌         |

## Management Services (Zigbee[[2]](#2) 2.2.4.\[2 - 5\])

|Primitive              |Request    |Confirm    |
|-----------------------|-----------|-----------|
|APSME-BIND             |❓         |❗         |
|APSME-UNBIND           |❓         |❗         |
|APSME-GET              |❓         |❓         |
|APSME-SET              |❓         |❓         |
|APSME-ADD-GROUP        |❓         |❌         |
|APSME-REMOVE-GROUP     |❓         |❌         |
|APSME-REMOVE-ALL-GROUPS|❎         |❌         |

# NWK

## Data Service (Zigbee[[2]](#2) 3.2.1)

|Primitive              |Request    |Confirm    |Indication |
|-----------------------|-----------|-----------|-----------|
|NLDE-DATA              |❎         |❎         |❎         |

## Management Services (Zigbee[[2]](#2) 3.2.2)

|Primitive                          |Request    |Confirm    |Indication |
|-----------------------------------|-----------|-----------|-----------|
|NLME-NETWORK-AND-PARENT-DISCOVERY  |❗         |❗         |-          |
|NLME-NETWORK-FORMATION             |❓         |❓         |-          |
|NLME-PERMIT-JOINING                |❓         |❓         |-          |
|NLME-START-ROUTER                  |❓         |❓         |-          |
|NLME-ED-SCAN                       |❓         |❓         |-          |
|NLME-JOIN                          |❓         |❓         |❓         |
|NLME-ADD-NEIGHBOR                  |❌         |❌         |-          |
|NLME-LEAVE                         |❓         |❓         |❓         |
|NLME-RESET                         |❓         |❓         |-          |
|NLME-SYNC                          |❓         |❓         |-          |
|NLME-GET                           |❓         |❓         |-          |
|NLME-SET                           |❓         |❓         |-          |
|NLME-NWK-STATUS                    |-          |-          |❓         |
|NLME-ROUTE-DISCOVERY               |❓         |❗         |-          |
|NLME-SET-INTERFACE                 |❌         |❌         |-          |
|NLME-GET-INTERFACE                 |❌         |❌         |-          |
