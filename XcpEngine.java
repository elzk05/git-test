/*
 * Copyright(c) 2019 PTYPE.CO,LTD. All rights reserved.
 *
 * This source code is protected by Republic of Korea and International copyright laws.
 * Reproduction and distribution of the source code without written permission of
 * the sponsor is prohibited.
 *
 * 본 소스는 대한민국 저작권법에 의해 보호를 받는 저작물이므로
 * PTYPE. CO, LTD.의 허락없이 무단전재와 무단 복제를 엄금합니다.
 */

package com.olivia.homesvr.p10_xcp;

import android.app.AlarmManager;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.Environment;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.support.v4.content.LocalBroadcastManager;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import com.olivia.homesvr.BuildConfig;
import com.olivia.homesvr.R;
import com.olivia.homesvr.p00_common.FileLogHelper;
import com.olivia.homesvr.p00_common.LowPrecisionTimer;
import com.olivia.homesvr.p00_common.PtDateTime;
import com.olivia.homesvr.p00_common.PtGlobal;
import com.olivia.homesvr.p00_common.PtLog;
import com.olivia.homesvr.p03_device.OliviaPref;
import com.olivia.homesvr.p03_device.Sensor;
import com.olivia.homesvr.p03_phone.PhoneInfo;
import com.olivia.homesvr.p10_xcp_events.OfcanEvent;
import com.olivia.homesvr.p10_xcp_events.UpgradeEvent;
import com.olivia.homesvr.p10_xcp_events.WeatherEvent;
import com.olivia.homesvr.p20_ha.HaGlobal;
import com.olivia.homesvr.p20_ha.HaSpec;
import com.olivia.homesvr.p20_ha.pojo.ProxyPojo;
import com.olivia.homesvr.p20_ha.pojo.TtaXiGas;
import com.olivia.homesvr.p20_ha.pojo.TtaXiLight;
import com.olivia.homesvr.p20_ha.pojo.TtaXiStbyPwrBrk;
import com.olivia.homesvr.p20_ha.pojo.XiStbyPwrBrk;
import com.olivia.homesvr.p20_ha.pojo.XiSysclein;
import com.olivia.homesvr.p20_ha.proxy.ProxyApi;
import com.olivia.homesvr.p20_ha.proxy.ProxyServer;
import com.olivia.homesvr.p20_ha.util.Tools;
import com.olivia.homesvr.p30_security.AesEngine;
import com.olivia.homesvr.p30_security.CertManager;
import com.olivia.homesvr.p30_security.NtpClient;
import com.olivia.homesvr.p30_security.OcspTrustManager;
import com.olivia.homesvr.p30_security.SecurityConstants;
import com.olivia.homesvr.s00_common.S00_20__dlg;
import com.olivia.homesvr.s00_common.S00_21__mmg_dlg;
import com.olivia.homesvr.s00_common.S00_23__mmg_exp_dlg;
import com.olivia.homesvr.s00_common.S00_app;
import com.olivia.homesvr.s07_contents.service.ZipUtils;
import com.olivia.homesvr.s10_setting.update.Version;

import org.apache.commons.lang3.StringUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.NetworkInterface;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import io.reactivex.Observable;
import io.reactivex.Observer;
import io.reactivex.annotations.NonNull;
import io.reactivex.disposables.Disposable;
import io.reactivex.schedulers.Schedulers;

import static com.olivia.homesvr.p03_device.OliviaPref.ADMIN__CERTMANAGER_ERROR_CODE;
import static com.olivia.homesvr.p03_device.OliviaPref.DEFAULT_USER__PRIMARY_PASSWORD;
import static com.olivia.homesvr.s01_home.launcher.MainActivity.getActivity;

/**
 * @brief The XcpEngine class

 probe sequence

Server            Lobby
  |<-- connect --- |
  |                |
  |                |
  |--- GATEWAY --> |
  |<-- GATEWAY --- |  // resp key
  |                |
  |                |  -------[start probe]------------
  |<-- SERVER  --- |
  |--- SERVER -->  |  // apply curtime ( it is alive )
  |                |
  |                |
  |<-- QRHNUM  --- |
  |--- QRHNUM -->  |  // cross check, my dong-ho is valid
  |                |
  |                |
  |<-- INSTALL --- |
  |--- INSTALL --> |  // get iptable info : iptable_ver ( ftp_info )
  |                |
  |                |
  |<-- UPGRADE --- |
  |--- UPGRADE --> |  // get upgrade info : pathname  ( ftp_info )
 */
public class XcpEngine extends XcpClientSession {
    private static final String TAG = XcpEngine.class.getSimpleName();
    private static final boolean DEBUG_SPEC = true;

    //public static final int TIMEOUT_WAIT_GATEWAY_FOR_PROBE = 3 * 1000;

    // begin kyeongilhan 2021-12-06 : 최초 gateway 수신 timeout 10초
    public static final int TIMEOUT_WAIT_GATEWAY_FOR_PROBE = 10 * 1000;

    public static final int TIMEOUT_ALIVE = 200*1000;   // org
//    public static final int TIMEOUT_ALIVE = 10 * 1000;   // test
//    public static final int TIMEOUT_ALIVE = 5 * 1000;   // test

    // begin kyeongilhan 2021-11-30 : tds3.0과 alive 로직 통일 (target=gateway 후 630초 대기. target=gateway 안오면 target=server 보내고 응답 없음 끊음)
    public static final int TIMEOUT_GATEWAY_ALIVE = 630*1000;

    ////////////////////////////////////////////////////////////////////////
    // 20210506 암호화 추가
    public enum ConnectionType {
        TCP ,
        AES,
        TLS,
        TLS_CERT,
        TLS_TEMP,
        CERT_MANAGER
    }

    ConnectionType mConnectionType = ConnectionType.TCP;
    ////////////////////////////////////////////////////////////////////////

    public static final int APP_MENU_INTERPHONE     = 0x01;
    public static final int APP_MENU_PSTN_PHONE     = 0x02;
    public static final int APP_MENU_FRONT_DOOR     = 0x03;
    public static final int APP_MENU_CALL_HISTORY   = 0x04;
    public static final int APP_MENU_VISITOR_LIST   = 0x05;
    public static final int APP_MENU_LIGHT          = 0x06;
    public static final int APP_MENU_GAS_VALVE      = 0x07;
    public static final int APP_MENU_HEATING        = 0x08;
    public static final int APP_MENU_STANDBYPOWER   = 0x09;
    public static final int APP_MENU_CURTAIN        = 0x10;
    public static final int APP_MENU_VENTILATOR     = 0x11;
    public static final int APP_MENU_AIRCONDITIONER = 0x12;
    public static final int APP_MENU_REALTIME_ENERGY= 0x13;
    public static final int APP_MENU_SECURITY_MODE  = 0x14; // n/a
    public static final int APP_MENU_CCTV           = 0x15;
    public static final int APP_MENU_EMERGENCY_CALL = 0x16;
    public static final int APP_MENU_CHILDREN_SAFETY= 0x17;
    public static final int APP_MENU_SEC_MODE_SET   = 0x18;
    public static final int APP_MENU_ENERGY         = 0x19;
    public static final int APP_MENU_NOTICE         = 0x21;
    public static final int APP_MENU_MGMT_FEE       = 0x22;
    public static final int APP_MENU_REPAIR         = 0x23;
    public static final int APP_MENU_ELEVATOR       = 0x24;
    public static final int APP_MENU_CAR_ACCESS     = 0x25;
    public static final int APP_MENU_PARKING        = 0x26;
    public static final int APP_MENU_PARCEL         = 0x27;
    public static final int APP_MENU_VOTE           = 0x28;
    public static final int APP_MENU_U_CITY         = 0x29; // n/a
    public static final int APP_MENU_MANUAL         = 0x30;
    public static final int APP_MENU_WEATHER        = 0x31;
    public static final int APP_MENU_MEMO           = 0x32;
    public static final int APP_MENU_SETTINGS       = 0x33; // n/a
    public static final int APP_MENU_REMOTE_SUPPORT = 0x35; // n/a
    public static final int APP_MENU_SECURITY_RECORD= 0x36;
    public static final int APP_MENU_PROGRESSIVE_TAX= 0x39;
    public static final int APP_MENU_FAMILY_SEARCH  = 0x40; // n/a
    public static final int APP_MENU_SCREEN_CLEAN   = 0x41;
    public static final int APP_MENU_ROOM_ENERGY    = 0x44;
    public static final int APP_MENU_SYSCLEIN       = 0x53;
    public static final int APP_MENU_SEC_HISTORY    = 0x54;
    public static final int APP_MENU_EVENT_LIST     = 0x55;
    public static final int APP_MENU_SCHEDULER      = 0x57;
    public static final int APP_MENU_DIGITAL_ALBUM  = 0x58;
    public static final int APP_MENU_MEDIA_PLAYER   = 0x59;
    public static final int APP_MENU_FILE_DOWNLOAD  = 0x60;
    public static final int APP_MENU_HEALTH_CARE    = 0x61;
    public static final int APP_MENU_ELECTRIC_CAR   = 0x62;
    public static final int APP_MENU_FMCS           = 0x63;
    public static final int APP_MENU_AIR_QUALITY    = 0x64;
    public static final int APP_MENU_LANGUAGE       = 0x65;
    public static final int APP_MENU_PASSWORD       = 0x66;
    public static final int APP_MENU_DISPLAY        = 0x67;
    public static final int APP_MENU_SOUND          = 0x69;
    public static final int APP_MENU_DOOR_SECURITY  = 0x6A;
    public static final int APP_MENU_MOVE           = 0x6B;
    public static final int APP_MENU_WIRELESS       = 0x6C;
    public static final int APP_MENU_SEC_PASSWORD   = 0x6D;
    public static final int APP_MENU_LICENCE        = 0x6E;
    public static final int APP_MENU_SILVER_CARE    = 0x70;
    public static final int APP_MENU_CAR_ALARM      = 0x71;
    public static final int APP_MENU_UPDATE         = 0x72;
    public static final int APP_MENU_ENVIRSENSOR    = 0x83; // CJH 2023-01-17 : 환경센서 추가, TDS 5.0과 동일하게 지정

    private static boolean mSpecFileLoaded = false;

    Context mContext;   // application context
    LocalBroadcastManager mLocalBcastMan;
    XcpApi mXcpApi;

    boolean mStarted;
    LowPrecisionTimer mProbeTimer;
    LowPrecisionTimer mAliveTimer;

    enum ProbeStep {
        Idle
        , wait_req_gateway
        , wait_rsp_server
        , wait_rsp_qrhnum
        , wait_rsp_install
        , wait_rsp_upgrade
        , probe_success
        , probe_fail
    }

    ProbeStep mProbeStep = ProbeStep.Idle;

    // cached message
    XcpMessage mXcpGateway;
    XcpMessage mXcpInstall;
//    XcpMessage mXcpUpgrade;

    //

    OliviaPref mSharedPreference;
    private String mServerIp;
    private int mServerPort;
    private int mBuildingNumber;
    private int mUnitNumber;
    private LocalBroadcastManager mBroadcastManager;
    private boolean mSpecFileDownloaded = false;
    private boolean mSpecUpdated;
    private boolean mLackInformation = false;

    //
    public static boolean mDebugMsg;
    public static int mRemoveLivingDimming = -1;

    /**
     * CJH 2023-01-05 옵션 추가, '9'인 경우 디밍 1, 2구 전체 삭제
     * CJH 2022-12-05 신동탄포레자이, 강동헤리치자이 디밍 삭제 옵션 추가
     * 월패드에 매립된 거실 조명 스위치의 경우 디밍 2회로가 고정이나
     * 건설에서 디밍 조명을 옵션으로 판매하여 1회로만 디밍으로 사용하려고 함.
     * 거실 조명 스위치에만 국한, 결국 option 값에 따라 해당 구를 강제로 일반 조명으로 처리.
     * @param groupId
     * @param index
     * @return
     */
    public static boolean isRemoveDimming(int groupId, int index) {
        // 거실 스위치만 한정
        if (groupId == 0x11) {
            if (mRemoveLivingDimming == 0x09 || mRemoveLivingDimming == index) {
                return true;
            }
        }
        return false;
    }

    private static XcpEngine sInstance;
    private static HaSpec sJsonSpec;
    private static XcpSpec sXmlSpec = new XcpSpec();
    private static Map<Integer, String> sMenuTree = null;
    public static WeatherEvent latestWeatherData;
    public static WeatherEvent latestWeatherSensorData;
    private final Object probeSyncObject = new Object();

    // begin kyeongilhan 2022-06-22 : 인증서 만료일 90일 전 갱신 실패 시 다시 갱신 시도하지 않고 단지서버 접속 하도록 flag 추가
    public static boolean isRenewTried = false;
    public static String resultCode;
    // end kyeongilhan 2022-06-22
    public static boolean restartFlag = false;
    private static Handler serviceRestartHandler;
    private final Handler certHandler = new Handler(Looper.getMainLooper());

    /**
     * 2022-07-14 CJH
     * 스펙 다운로드 중에 HA 업데이트를 진행하면 안되므로
     * 1분동안 백그라운드에서 체크 후 업데이트를 진행
     */
    private class UpdateCheckThread implements Runnable {
        String version;
        int nCount;
        int errCode;

        public UpdateCheckThread (String s) {
            this.version = s;
            this.nCount = 0;
            // default is error code
            this.errCode = Xcp.UPDATE_ERR_ALREADY_UPDATING;
        }

        public void run() {
            while(nCount++ < 12) {
                if(!PhoneInfo.mPhoneIsUpdating) {
                    errCode = Xcp.UPDATE_START_UPGRADE;
                    Intent upgradeActivity = new Intent();
                    upgradeActivity.setClassName(mContext, "com.olivia.homesvr.s10_setting.update.Update_Activity");
                    mContext.startActivity(upgradeActivity);
                    break;
                } else {
                    try {
                        Thread.sleep(1000 * 5); // (5sec * 12) = 1 min 수행
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
            UpgradeMessage.sendUpdateResult(errCode);
        }
    }

    private static final Runnable serviceRestartRunnable = new Runnable() {
        @Override
        public void run() {
            if(!restartFlag) {
                try {
                    if(XcpEngine.getInstance() == null) {
                        S00_app.getInstance().startService(new Intent(S00_app.getInstance(), XcpEngine.class));
                    }
                    else {
                        Log.e(TAG, "Restarting XcpEngine Service");
                        restartFlag = true;
                        Intent xcpServiceIntent = new Intent(S00_app.getInstance(), XcpEngine.class);
                        S00_app.getInstance().stopService(xcpServiceIntent);
                    }

                    serviceRestartHandler = null;
                } catch (Exception e) {
                    S00_app.getInstance().startService(new Intent(S00_app.getInstance(), XcpEngine.class));
                }
            } else {
                Intent xcpServiceIntent = new Intent(S00_app.getInstance(), XcpEngine.class);
                S00_app.getInstance().stopService(xcpServiceIntent);
            }
        }
    };

    /* jyahn */
    public static synchronized HaSpec createJsonSpec(Context context) {

        if(sMenuTree == null) {
            sMenuTree = new LinkedHashMap<Integer, String>() {
                {
                    put(APP_MENU_INTERPHONE, context.getResources().getString(R.string.s01_app_03_01_interphone));
                    put(APP_MENU_PSTN_PHONE, context.getResources().getString(R.string.s01_app_03_02_pstn));
                    put(APP_MENU_FRONT_DOOR, context.getResources().getString(R.string.s01_app_03_03_door));
                    put(APP_MENU_CALL_HISTORY, context.getResources().getString(R.string.s01_app_03_04_call_list));
                    put(APP_MENU_VISITOR_LIST, context.getResources().getString(R.string.s01_app_03_05_visitors));
                    put(APP_MENU_LIGHT, context.getResources().getString(R.string.s01_app_02_01_light));
                    put(APP_MENU_GAS_VALVE, context.getResources().getString(R.string.s01_app_02_02_gas));
                    put(APP_MENU_HEATING, context.getResources().getString(R.string.s01_app_02_03_heat));
                    put(APP_MENU_STANDBYPOWER, context.getResources().getString(R.string.s01_app_02_04_sp));
                    put(0x0A, "");
                    put(0x0B, "");
                    put(0x0C, "");
                    put(0x0D, "");
                    put(0x0E, "");
                    put(0x0F, "");
                    put(APP_MENU_CURTAIN, context.getResources().getString(R.string.s01_app_02_08_curtain));
                    put(APP_MENU_VENTILATOR, context.getResources().getString(R.string.s01_app_02_05_fan));
                    put(APP_MENU_AIRCONDITIONER, context.getResources().getString(R.string.s01_app_02_07_con));
                    put(APP_MENU_REALTIME_ENERGY, context.getResources().getString(R.string.s01_app_04_01_realtime));
                    put(APP_MENU_SECURITY_MODE, "sctyset");
                    put(APP_MENU_CCTV, context.getResources().getString(R.string.s01_app_05_06_cctv));
                    put(APP_MENU_EMERGENCY_CALL, context.getResources().getString(R.string.s01_app_05_02_emcall));
                    put(APP_MENU_CHILDREN_SAFETY, context.getResources().getString(R.string.s01_app_05_08_kids));
                    put(APP_MENU_SEC_MODE_SET, context.getResources().getString(R.string.s01_app_05_01_smode));
                    put(APP_MENU_ENERGY, context.getResources().getString(R.string.s01_app_04_02_energy));
                    put(0x1A, "");
                    put(0x1B, "");
                    put(0x1C, "");
                    put(0x1D, "");
                    put(0x1E, "");
                    put(0x1F, "");
                    put(0x20, "");
                    put(APP_MENU_NOTICE, context.getResources().getString(R.string.s01_app_06_02_notice));
                    put(APP_MENU_MGMT_FEE, context.getResources().getString(R.string.s01_app_06_04_charge));
                    put(APP_MENU_REPAIR, context.getResources().getString(R.string.s01_app_06_03_repair));
                    put(APP_MENU_ELEVATOR, context.getResources().getString(R.string.s01_app_08_01_elevator));
                    put(APP_MENU_CAR_ACCESS, context.getResources().getString(R.string.s01_app_08_02_carinout));
                    put(APP_MENU_PARKING, context.getResources().getString(R.string.s01_app_08_03_parking));
                    put(APP_MENU_PARCEL, context.getResources().getString(R.string.s01_app_08_04_parcel));
                    put(APP_MENU_VOTE, context.getResources().getString(R.string.s01_app_08_06_vote));
                    put(APP_MENU_U_CITY, "");
                    put(0x2A, "");
                    put(0x2B, "");
                    put(0x2C, "");
                    put(0x2D, "");
                    put(0x2E, "");
                    put(0x2F, "");
                    put(APP_MENU_MANUAL, context.getResources().getString(R.string.s01_app_06_05_manual));
                    put(APP_MENU_WEATHER, context.getResources().getString(R.string.s01_app_07_01_weather));
                    put(APP_MENU_MEMO, context.getResources().getString(R.string.s01_app_07_04_memo));
                    put(APP_MENU_SETTINGS, "");
                    put(0x34, "");
                    put(APP_MENU_REMOTE_SUPPORT, "");
                    put(APP_MENU_SECURITY_RECORD, context.getResources().getString(R.string.s01_app_05_05_rec));
                    put(0x37, "");
                    put(0x38, "");
                    put(APP_MENU_PROGRESSIVE_TAX, context.getResources().getString(R.string.s01_app_04_04_progressive));
                    put(0x3A, "");
                    put(0x3B, "");
                    put(0x3C, "");
                    put(0x3D, "");
                    put(0x3E, "");
                    put(APP_MENU_FAMILY_SEARCH, "");
                    put(APP_MENU_SCREEN_CLEAN, context.getResources().getString(R.string.s01_app_10_06_clean));
                    put(0x42, "");
                    put(0x43, "");
                    put(APP_MENU_ROOM_ENERGY, context.getResources().getString(R.string.s01_app_04_03_room));
                    put(0x45, "");
                    put(0x46, "");
                    put(0x47, "");
                    put(0x48, "");
                    put(0x49, "");
                    put(0x4A, "");
                    put(0x4B, "");
                    put(0x4C, "");
                    put(0x4D, "");
                    put(0x4E, "");
                    put(0x50, "");
                    put(0x51, "");
                    put(0x52, "");
                    put(APP_MENU_SYSCLEIN, context.getResources().getString(R.string.s01_app_02_06_sysclein));
                    put(APP_MENU_SEC_HISTORY, context.getResources().getString(R.string.s01_app_05_04_slist));
                    put(APP_MENU_EVENT_LIST, context.getResources().getString(R.string.s01_app_06_01_event));
                    put(0x56, "");
                    put(APP_MENU_SCHEDULER, context.getResources().getString(R.string.s01_app_07_03_schedule));
                    put(APP_MENU_DIGITAL_ALBUM, context.getResources().getString(R.string.s01_app_07_05_digitalframe));
                    put(APP_MENU_MEDIA_PLAYER, context.getResources().getString(R.string.s01_app_07_06_mediaplayer));
                    put(0x5A, "");
                    put(0x5B, "");
                    put(0x5C, "");
                    put(0x5D, "");
                    put(0x5E, "");
                    put(APP_MENU_FILE_DOWNLOAD, context.getResources().getString(R.string.s01_app_07_07_filedownload));
                    put(APP_MENU_HEALTH_CARE, context.getResources().getString(R.string.s01_app_07_08_healthcare));
                    put(APP_MENU_ELECTRIC_CAR, context.getResources().getString(R.string.s01_app_07_09_electroniccar));
                    put(APP_MENU_FMCS, context.getResources().getString(R.string.s01_app_07_10_fmcs));
                    put(APP_MENU_AIR_QUALITY, context.getResources().getString(R.string.s01_app_07_02_air));
                    put(APP_MENU_LANGUAGE, context.getResources().getString(R.string.s01_app_10_03_lang));
                    put(APP_MENU_PASSWORD, context.getResources().getString(R.string.s01_app_10_04_pwd));
                    put(APP_MENU_DISPLAY, context.getResources().getString(R.string.s01_app_10_05_disp));
                    put(0x68, "");
                    put(APP_MENU_SOUND, context.getResources().getString(R.string.s01_app_10_07_sound));
                    put(APP_MENU_DOOR_SECURITY, context.getResources().getString(R.string.s01_app_10_08_doorphone));
                    put(APP_MENU_MOVE, context.getResources().getString(R.string.s01_app_10_10_move));
                    put(APP_MENU_WIRELESS, context.getResources().getString(R.string.s01_app_10_11_wireless));
                    put(APP_MENU_SEC_PASSWORD, context.getResources().getString(R.string.s01_app_10_12_secpwd));
                    put(APP_MENU_LICENCE, context.getResources().getString(R.string.s01_app_10_13_license));
                    put(0x6F, "");
                    put(APP_MENU_SILVER_CARE, context.getResources().getString(R.string.s01_app_10_14_silvercare));
                    put(APP_MENU_CAR_ALARM, context.getResources().getString(R.string.s01_app_10_15_caralarm));
                    put(APP_MENU_UPDATE, context.getResources().getString(R.string.s01_app_10_09_update));
                    put(APP_MENU_ENVIRSENSOR, context.getResources().getString(R.string.s01_app_02_10_envirsensor)); // CJH 2023-01-17 : 환경센서 추가
                }
            };
        } // sMenuTree == null

        if(sJsonSpec == null) {

            // begin CJH 2023-01-17 : 환경센서 추가 (schema->for mst, menu->for xml parsing)
            if (BuildConfig.IS_XI) {
                sJsonSpec = fromJson(Tools.stringFromResource(context.getResources(),
                        Tools.isEmulator() ? R.raw.spec_e0_avd_to_simul_loopbak : R.raw.spec_t0_tgt_to_dev));
            } else {
                sJsonSpec = fromJson(Tools.stringFromResource(context.getResources(),
                        Tools.isEmulator() ? R.raw.spec_e0_avd_to_simul_loopbak : R.raw.spec_t0_tgt_to_dev_2));
            }
            // end CJH 2023-01-17

            boolean result;
            String currentSpecPath = OliviaPref.getInstance().getAsciiString(OliviaPref.ADMIN__SPECIFICATION_PATH, "");
            if(currentSpecPath==null || currentSpecPath.equals("")) { //initial install.
                Log.e(TAG, "use default specification");

                // CJH 2023-05-30 : 'A'타입으로 초기화 후 기본 스펙을 load한다.
                OliviaPref.getInstance().put(OliviaPref.ADMIN__APT_TYPE, "A");

                // 220404 CJH 평택역SK 모델하우스용 기본 스펙 추가
                if(OliviaPref.getCustomizeSK()) {
                    result = sXmlSpec.loadXml(PtGlobal.stringFromResource(context, R.raw.specification_2_0_3_sk));
                } else {
                    result = sXmlSpec.loadXml(PtGlobal.stringFromResource(context, R.raw.specification_2_0_3_full));
                }
            }else {
                Log.e(TAG, "use new specification. path : " + currentSpecPath);
                result = sXmlSpec.loadXmlPath(currentSpecPath);
                if(!result) {
                    File file_to_be_erased = new File(currentSpecPath);
                    if(file_to_be_erased.exists()) {
                        file_to_be_erased.delete();
                    }
                    OliviaPref.getInstance().put(OliviaPref.ADMIN__SPECIFICATION_PATH,"");
                    //20210120 spec type mismatch 방지
                    OliviaPref.getInstance().put(OliviaPref.ADMIN__APT_TYPE, "A");
                    Log.e(TAG, "use default specification");
                    result = sXmlSpec.loadXml(PtGlobal.stringFromResource(context, R.raw.specification_2_0_3_full));
                }
            }

            if(result) {
                // begin CJH 2023-05-30 : 다운로드 받은 스펙 파일이 잘못된 경우에는 파일을 지우기 때문에
                //                        해당 func에서는 exception이 발생하지 않으므로 try-catch로만 감싸준다.
                try {
                    mergeXmlSpecToJsonSpec();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                // end CJH 2023-05-30
            }
        }

        return sJsonSpec;
    }

    public static void restartService() {
        try {
            if (serviceRestartHandler == null) {
                serviceRestartHandler = new Handler(Looper.getMainLooper());
            }
            Log.e(TAG, "Restarting XcpEngine Using Handler");
            serviceRestartHandler.removeCallbacks(serviceRestartRunnable);
            serviceRestartHandler.postDelayed(serviceRestartRunnable, 3000);
        }
        catch(Exception e) {
            if(!restartFlag) {
                restartFlag = true;
                Log.e(TAG, "Restarting XcpEngine directly");
                Intent xcpServiceIntent = new Intent(S00_app.getInstance(), XcpEngine.class);
                xcpServiceIntent.putExtra("ocsp", false);
                if(XcpEngine.getInstance() == null) {
                    S00_app.getInstance().startService(xcpServiceIntent);
                }
                else {
                    S00_app.getInstance().stopService(xcpServiceIntent);
                }
            }
        }
    }

    public static void restartWithOcspResult(String result) {
        if(!restartFlag) {
            Intent xcpServiceIntent = new Intent(S00_app.getInstance(), XcpEngine.class);
            xcpServiceIntent.putExtra("ocsp", result);

            try {
                if (XcpEngine.getInstance() == null) {
                    S00_app.getInstance().startService(xcpServiceIntent);
                } else {
                    Log.e(TAG, "Restarting XcpEngine Service");
                    restartFlag = true;
                    isPingSuccess = false;
                    S00_app.getInstance().stopService(xcpServiceIntent);
                }

                serviceRestartHandler = null;
            } catch (Exception e) {
                S00_app.getInstance().startService(xcpServiceIntent);
            }
        }
    }

    public static String getSpecificationVersion() {
        if(sXmlSpec != null)
            return sXmlSpec.getVersion();
        return "N/A";
    }

    public static String getSpecificationType() {
        if(sXmlSpec != null)
            return sXmlSpec.getApartmentType();
        return "";
    }


    private static HaSpec fromJson(String json)
    {
        HaSpec spec = new HaSpec();
        if (!spec.parseJson(json))
        {
            PtLog.e(TAG, "fail!, parse json");
            return null;
        }

        return spec;
    }

    // jyahn moved to onCreate() method..
//    public static synchronized XcpEngine getInstance() {
//        if (sInstance == null) {
//            HandlerThread handlerThread = new HandlerThread("XcpEngine");
//            handlerThread.start();
//            sInstance = new XcpEngine(handlerThread.getLooper());
//        }
//        return sInstance;
//    }

    SharedPreferences.OnSharedPreferenceChangeListener mPreferenceListener =
            (sharedPreferences, s) -> {
                if(s.equals(OliviaPref.ADMIN__COMPLEX_SERVER_IP)
                        || s.equals(OliviaPref.ADMIN__COMPLEX_SERVER_PORT)
                        || s.equals(OliviaPref.ADMIN__BUILDING_NUMBER)
                        || s.equals(OliviaPref.ADMIN__UNIT_NUMBER)) {
                    // don't know what to do!!!

                }
                else if(s.equals(OliviaPref.ADMIN__SETTING_SAVED)) {
                    // this will be updated when Network setting is changed and updated from "S11_01__network"
                    //Log.d(TAG, "Shared Preference has been changed");
                    if(XcpEngine.canCommunicate())
                        reconnect();
                    else
                        startConnection();
                } else if (s.equals(OliviaPref.ADMIN__NTP_SUCCESS)) {
                    // 20210513 NTP 성공시에만 단지서버와 통신 시작하도록 sharedpreference 사용
                    //Log.d(TAG, "Shared Preference has been changed");
                    OliviaPref oliviaPref = OliviaPref.getInstance();
                    if (oliviaPref.getBoolean(OliviaPref.ADMIN__NTP_SUCCESS, false)) {
                        Log.e(TAG, "[NTP] NTP SUCCESS!!");
                        if(XcpEngine.canCommunicate())
                            reconnect();
                        else
                            startConnection();
                    }
                }
            };

    public static  XcpEngine getInstance() {
        return sInstance;
    }

    public static boolean canCommunicate() {
        if(sInstance != null) {
            return (sInstance.isStarted() && sInstance.isConnected() && sInstance.isProbeDone());
        }
        return false;
    }

    public XcpEngine() {
        super();
        sInstance = this;
        mStarted = false;
        mLackInformation = false;
        super.mState = State.Unconnected;
        mProbeStep = ProbeStep.Idle;
    }

    public ContentResolver getContentResolver() {
        return mContext.getContentResolver();
    }

    public XcpApi getXcpApi() {
        return mXcpApi;
    }

    private boolean isStarted() {
        return mStarted;
    }

    public Context getContext() {
        return mContext;
    }

    public boolean isAliveTimerRunning() {

        if(isProbeDone()) {
            //Log.d(TAG, "mProbe is done Rx packet count -> " + XcpClientSession.getRxPacketCount());
            if(mAliveTimer != null)
                return mAliveTimer.isActive();
            else
                return false;
        }

        if(mLackInformation)
            return true;

        Log.d(TAG, "mStarted -> " + mStarted + ", mState -> " + super.mState + ", mProbeStep -> " + mProbeStep);

        if(mStarted) {
            return (super.mState != State.Unconnected);
        }

        return false;
    }

    public static boolean isSpecFileLoaded() { return mSpecFileLoaded; }

    private boolean isProbeDone() {
        return (mProbeStep == ProbeStep.probe_success);
    }

    public static boolean isPingSuccess = true;

    /**
     * Service has been created!!
     */
    @Override
    public void onCreate() {
        super.onCreate();

        Log.d(TAG, "XcpEngine Created!!");

        sInstance = this;
        mContext = getApplicationContext();
        //PtLog.i(TAG, "mContext:%s", mContext);

        mLocalBcastMan = LocalBroadcastManager.getInstance(mContext);
        //PtLog.i(TAG, "mLocalBcastMan:%s", mLocalBcastMan);

        mXcpApi = new XcpApi(this);
        mBroadcastManager = LocalBroadcastManager.getInstance(mContext);

        mProbeTimer = new LowPrecisionTimer("probeTimer");
        mProbeTimer.setSingleShot(true);

        /////////////////////////////////////////////////////
        // 클라이언트에서는 매 200 초 마다 Alive 패킷를 전송하여 단지서버와의 연결을 유지한다.
        // begin kyeongilhan 2021-12-06 : 630초 timer로 변경 (3.0과 동일한 로직)
        mAliveTimer = new LowPrecisionTimer("aliveTimer");
        mAliveTimer.setSingleShot(false);
        mAliveTimer.setInterval(TIMEOUT_GATEWAY_ALIVE);
        //mAliveTimer.setInterval(TIMEOUT_ALIVE);
        /////////////////////////////////////////////////////

        mSharedPreference = OliviaPref.getInstance();

        createJsonSpec(mContext);
        if(mBroadcastManager != null) {
            mBroadcastManager.sendBroadcast(new Intent(PhoneInfo.ACTION_XCP_ENGINE_SPEC_LOADED));
        }

        mSharedPreference.getPref().registerOnSharedPreferenceChangeListener(mPreferenceListener);

        restartFlag = false;

        // 20210513 NTP 추가
        // NTP 일 경우에는 connection setup 전에 NTP process를 타야함
        // 시스템 시간 정보 받아왔을때만 단지서버와 통신
        if (OliviaPref.isEnableTLS()) {
            // ntp 프로세스
            OliviaPref.setValue(OliviaPref.ADMIN__NTP_SUCCESS, false);
            ntpRetryCount = 30;
            ntpProcess();
        } else {
            if(!startConnection()) {
                Log.e(TAG, "error on starting connection...");
            }
        }
    }

    public void setRestartFlag(boolean flag) {
        restartFlag = flag;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // begin kyeongilhan 2022-06-22 : 갱신 무한 재시도 막기
        if (intent != null) {
            if (intent.getStringExtra("isRenewTried") != null) {
                switch (intent.getStringExtra("isRenewTried")) {
                    case "true":
                        isRenewTried = true;
                        break;

                    default:
                        break;
                }
            }

            if (intent.getStringExtra("ocsp") != null) {
                switch (intent.getStringExtra("ocsp")) {
                    case "false":
                        isPingSuccess = false;
                        break;

                    default:
                        isPingSuccess = true;
                        break;
                }
            } else isPingSuccess = true;

            resultCode = intent.getStringExtra("result");
        }

        // end kyeongilhan 2022-06-22
        return super.onStartCommand(intent, flags, startId);
    }

    @Override
    public void onDestroy() {
        mSharedPreference.getPref().unregisterOnSharedPreferenceChangeListener(mPreferenceListener);
        stopConnection();
        /////////////////////////////////////////////////////////////
        synchronized (probeSyncObject) {
            if (mProbeTimer != null)
                mProbeTimer.stop();
            mProbeTimer = null;
        }
        if(mAliveTimer != null)
            mAliveTimer.stop();
        mAliveTimer = null;
        if(mXcpApi != null)
            mXcpApi.destroy();
        mXcpApi = null;
        /////////////////////////////////////////////////////////////
        super.onDestroy();
        sInstance = null;
        if(restartFlag) {
            if (!isPingSuccess) startService(new Intent(getApplicationContext(), XcpEngine.class).putExtra("ocsp", "false"));
            else startService(new Intent(getApplicationContext(), XcpEngine.class));
        }
    }
    //...

    public boolean startConnection() {

        if ( PtGlobal.isEmulator() ) {
            mServerIp = mSharedPreference.get(OliviaPref.ADMIN__COMPLEX_SERVER_IP, "14.35.204.33");
            if(StringUtils.isEmpty(mServerIp)) mServerIp = "14.35.204.33";
            mServerPort = mSharedPreference.getInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.PORT);
            if(mServerPort == 0) mServerPort = Xcp.PORT;
            mBuildingNumber = mSharedPreference.getInt(OliviaPref.ADMIN__BUILDING_NUMBER, 101);
            if(mBuildingNumber == 0) mBuildingNumber = 101;
            mUnitNumber = mSharedPreference.getInt(OliviaPref.ADMIN__UNIT_NUMBER, 105);
            if(mUnitNumber == 0) mUnitNumber = 1503;
        }
        else {
            mServerIp = mSharedPreference.get(OliviaPref.ADMIN__COMPLEX_SERVER_IP, OliviaPref.Default_COMPLEX_SERVER);
            mServerPort = mSharedPreference.getInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.PORT);

            //20210510 buildconfig로 포트 강제 지정
            /*if (BuildConfig.ENABLE_AES) {
                Log.d(TAG, "BuildConfig : ENABLE_AES , set port 35001");
                mServerPort = Xcp.AES_PORT;
                mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.AES_PORT);
            }

            if (BuildConfig.ENABLE_TLS) {
                Log.e(TAG, "BuildConfig : ENABLE_TLS , set port 35011");
                mServerPort = Xcp.TLS_PORT;
                mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_PORT);

                // 20210513 global에 mac주소 저장
                SecurityConstants.WALLPAD_MAC_ADDRESS = getMacAddress();
            }*/

            // 20210513 global에 mac주소 저장
            SecurityConstants.WALLPAD_MAC_ADDRESS = getMacAddress();

            //20210506 암호화 추가
            switch (mServerPort) {
                case Xcp.PORT:
                    mConnectionType = ConnectionType.TCP;
                    initNormalBootstrap();
                    break;

                case Xcp.AES_PORT:
                    mConnectionType = ConnectionType.AES;
                    initNormalBootstrap();
                    break;

                case Xcp.TLS_CERT_PORT:
                    mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_PORT);
                case Xcp.TLS_PORT:
                    mConnectionType = ConnectionType.TLS;
                    CertManager certManager = CertManager.getInstance();

                    // begin kyeongilhan 2023-02-15 : 기본은 ocsp trustmanager 사용
                    // handshake 과정에서 ocsp exception 날 경우에만 non-ocsp 로 재설정 하고 연결 재시도

                    if (certManager.loadPfxCert(getApplicationContext())) {

                        Log.e(TAG, "[TLS] Load PFX Cert Success!");
                        //pfx 인증서로 35011 포트 접속
                        if (!isPingSuccess) {
                          if (!init2wayNonOcspSslBootstrap()) {
                              Log.e(TAG, "[TLS] Cert Load Error , set port 35100");
                              // 실패하면 35100 포트로 변경
                              mConnectionType = ConnectionType.TLS_CERT;
                              mServerPort = Xcp.TLS_CERT_PORT;
                              mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_CERT_PORT);
                              init1wayNonOcspSslBootstrap();
                          }
                        } else if (!init2waySslBootstrap()) {
                            Log.e(TAG, "[TLS] Cert Load Error , set port 35100");
                            // 실패하면 35100 포트로 변경
                            mConnectionType = ConnectionType.TLS_CERT;
                            mServerPort = Xcp.TLS_CERT_PORT;
                            mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_CERT_PORT);
                            init1waySslBootstrap();
                        }
                    } else if (certManager.isPfxCertDueToExpire(getApplicationContext())) {
                        // begin kyeongilhan 2022-09-27 : 무조건 일반 접속으로. 갱신은 분산 로직을 타야만 한다
                        // 이 로직은 인증서가 만료되지 않았을 경우에만 타야 한다 (만료일 1일 이상 남았을때만..)
                        Log.e(TAG, "[TLS] This Certification is due to expiring.. Try Normal TLS Connection Process..");
                        if (certManager.loadExpiredPfxCert(getApplicationContext())) {
                            Log.e(TAG, "[TLS] Load PFX Cert Success!");
                            //pfx 인증서로 35011 포트 접속
                            if (!isPingSuccess) {
                                if (!init2wayNonOcspSslBootstrap()) {
                                    Log.e(TAG, "[TLS] Cert Load Error , set port 35100");
                                    // 실패하면 35100 포트로 변경
                                    mConnectionType = ConnectionType.TLS_CERT;
                                    mServerPort = Xcp.TLS_CERT_PORT;
                                    mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_CERT_PORT);
                                    init1wayNonOcspSslBootstrap();
                                }
                            } else if (!init2waySslBootstrap()) {
                                Log.e(TAG, "[TLS] Cert Load Error , set port 35100");
                                // 실패하면 35100 포트로 변경
                                mConnectionType = ConnectionType.TLS_CERT;
                                mServerPort = Xcp.TLS_CERT_PORT;
                                mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_CERT_PORT);
                                init1waySslBootstrap();
                            }
                        } else {
                            Log.e(TAG, "[TLS] Cert Load Error , set port 35100");
                            // 실패하면 35100 포트로 변경
                            mConnectionType = ConnectionType.TLS_CERT;
                            mServerPort = Xcp.TLS_CERT_PORT;
                            mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_CERT_PORT);
                            init1waySslBootstrap();
                        }
                    } else if (certManager.isPfxCertExpired(getApplicationContext())) {
                        if (isRenewTried) {
                            // 기존에 있던 인증서를 지워버린다. 임시 인증서 상태로 바꾸기
                            certManager.deleteExistingCert(getApplicationContext());
                            Log.e(TAG, "[TLS] Cert Load Error , set port 35100");
                            // 35100 포트로 변경
                            mConnectionType = ConnectionType.TLS_CERT;
                            mServerPort = Xcp.TLS_CERT_PORT;
                            mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_CERT_PORT);
                            init1waySslBootstrap();
                        } else {
                            // 인증서 만료됐을 경우 바로 재발급 시도 해야 함
                            Log.e(TAG, "[TLS] This Certification is due to expired.. Try ReIssuance Process..");
                            // 단지서버 접속 엔진 중지
                            Intent xcpServiceIntent = new Intent(S00_app.getInstance(), XcpEngine.class);
                            restartFlag = false;
                            S00_app.getInstance().stopService(xcpServiceIntent);

                            // 갱신서버 접속 엔진 시작
                            Intent iotCertServiceIntent = new Intent(S00_app.getInstance(), IoTCertEngine.class);
                            iotCertServiceIntent.putExtra("type", IoTCertEngine.AuthType.expireReissuance);
                            S00_app.getInstance().startService(iotCertServiceIntent);
                        }
                    } else if (certManager.loadTempCert(getApplicationContext())) {
                        Log.e(TAG, "[TLS] Load Temp Cert Success!");
                        mConnectionType = ConnectionType.TLS_TEMP;
                        // 임시 인증서로 35011 포트 접속
                        if (!isPingSuccess) {
                            if (!init2wayTempNonOcspSslBootstrap()) {
                                Log.e(TAG, "[TLS] Cert Load Error , set port 35100");
                                // 실패하면 35100 포트로 변경
                                mConnectionType = ConnectionType.TLS_CERT;
                                mServerPort = Xcp.TLS_CERT_PORT;
                                mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_CERT_PORT);
                                init1wayNonOcspSslBootstrap();
                            }
                        } else if (!init2wayTempSslBootstrap()) {
                            Log.e(TAG, "[TLS] Cert Load Error , set port 35100");
                            // 실패하면 35100 포트로 변경
                            mConnectionType = ConnectionType.TLS_CERT;
                            mServerPort = Xcp.TLS_CERT_PORT;
                            mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_CERT_PORT);
                            init1waySslBootstrap();
                        }
                    } else {
                        Log.e(TAG, "Cert is Not Exist!! set Port to Cert Download");
                        // 35100 접속하여 인증서 다운로드
                        mConnectionType = ConnectionType.TLS_CERT;
                        mServerPort = Xcp.TLS_CERT_PORT;
                        mSharedPreference.putInt(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_CERT_PORT);
                        init1wayNonOcspSslBootstrap();
                    }
                    break;
                    // TLS라면.. 인증서를 확인하여 없으면 먼저 35100에 1-way TLS로 접속한다
            }

            Log.e(TAG, "[XCP] Connection Type = " + mConnectionType);

            mBuildingNumber = mSharedPreference.getInt(OliviaPref.ADMIN__BUILDING_NUMBER, 0);
            mUnitNumber = mSharedPreference.getInt(OliviaPref.ADMIN__UNIT_NUMBER, 0);
        }

        if(StringUtils.isEmpty(mServerIp)) {
            if ( PtGlobal.isEmulator() )
                Toast.makeText(mContext, R.string.s00_proxy_empty_serverip, Toast.LENGTH_SHORT).show();
            showNetworkSettingActivity();
            mLackInformation = true;
            return false;
        }
        else if(mServerPort <= 0 || mServerPort > 65535) {
            if ( PtGlobal.isEmulator() )
                Toast.makeText(mContext, getString(R.string.s00_proxy_port_number_out_of_range) + " [" + mServerPort + "]", Toast.LENGTH_SHORT).show();
            showNetworkSettingActivity();
            mLackInformation = true;
            return false;
        }
        else if(mBuildingNumber <= 0  || mBuildingNumber >= 9999 ) {
            if ( PtGlobal.isEmulator() )
                Toast.makeText(mContext, getString(R.string.s00_proxy_building_number_out_of_range) + " [" + mBuildingNumber + "]", Toast.LENGTH_SHORT).show();
            showNetworkSettingActivity();
            mLackInformation = true;
            return false;
        }
        // begin CJH 2022-11-02 : 호 length 5자리로 늘림
        else if(mUnitNumber <= 0  /*|| mUnitNumber >= 9999*/ ) {
        // end CJH 2022-11-02
            if ( PtGlobal.isEmulator() )
                Toast.makeText(mContext, getString(R.string.s00_proxy_unit_number_out_of_range) + " [" + mUnitNumber + "]", Toast.LENGTH_SHORT).show();
            showNetworkSettingActivity();
            mLackInformation = true;
            return false;
        }

        mLackInformation = false;

        if(!mStarted) {
            mStarted = true;
            mSpecFileDownloaded = false;
            mHandler.postDelayed(this::startImpl, 1000);
        }
        else {
            if(state() == State.Connected) {
                stopConnection();
                mHandler.postDelayed(this::startImpl, 5000);
            }
            else {
                // just change host names and stuff...
                super.connect(mBuildingNumber, mUnitNumber, mServerIp, mServerPort);
            }
        }
        return mStarted;
    }

    private void stopConnection() {
        if(mStarted) {
            mStarted = false;
            mHandler.post(this::stopImpl);
        }
    }

    private void showNetworkSettingActivity() {
//        Intent intent = new Intent(mContext, S11_main.class);
//        String uri = new Uri.Builder()
//                .appendQueryParameter("appname", "S11_01__network")
//                .toString();
//        intent.putExtra("uri", uri );
//        mContext.startActivity(intent);
    }

    private void startImpl() {
        if ( PtGlobal.isEmulator() ) {
            LOG_TX = true;
            LOG_RX = true;
        }

            // 100 동 105 호 works...
//            TEST_WIRED_LAN_IPV4_ADDRESS = "111.111.100.106";  // jyahn
//            super.connect(100, 106, "192.168.10.252", Xcp.PORT);
//
//            TEST_WIRED_LAN_IPV4_ADDRESS = "111.111.100.107";  // dhlim
//            super.connect(100, 107, "192.168.10.252", Xcp.PORT);
        super.connect(mBuildingNumber, mUnitNumber, mServerIp, mServerPort);
    }

    private void stopImpl() {
        super.disconnect();
    }

    private void doNotify(XcpMessage msg) {
        PtLog.e(TAG, "doNotify", msg.target());
//        Intent
//        mLocalBcastMan.sendBroadcast();
    }

    @Override
    protected void onStateChanged(State oldState, State newState) {
        switch (newState) {
        case Connected:
            mXcpGateway = null;
            mXcpInstall = null;
//            mXcpUpgrade = null;
            doProbe(ProbeStep.wait_req_gateway);
            break;
        case Unconnected:
            if(mAliveTimer != null)
                mAliveTimer.stop();
            doProbe(ProbeStep.Idle);
            break;
        }
    }

    void doProbe(ProbeStep step) {
        synchronized (probeSyncObject) {
            if (mProbeTimer == null) {
                Log.e(TAG, "probe timer is null.. probably restarting...");
                return;
            }

            XcpMessage req = null;
            switch (step) {
                case wait_req_gateway:
                    PtLog.AssertCatch(isConnected());
                    PtLog.AssertCatch(mProbeStep == ProbeStep.Idle);

                    // wait for S->C target=gateway
                    mProbeStep = step;
                    mProbeTimer.setOnTimeoutListener((t) -> {
                        // for prevent TCP half open state.
                        PtLog.e(TAG, "fail!, probe() : TIMEOUT_WAIT_GATEWAY_FOR_PROBE");
                        doProbe(ProbeStep.probe_fail);
                        // TODO : 210914 timeout 늘리기 -> 타건설은 늘려야할듯
                    }).start(TIMEOUT_WAIT_GATEWAY_FOR_PROBE);
                    break;
                case wait_rsp_server:
                    mProbeStep = step;
                    mProbeTimer.stop();

                    req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__SERVER);
                    request(req, (reply) -> {
                        if (!reply.isOk()) {
                            PtLog.e(TAG, "fail!, probe() : wait_rsp_server");
                            doProbe(ProbeStep.probe_fail);
                            return;
                        }
                        on_rsp_SERVER(reply.response());
                        doProbe(ProbeStep.wait_rsp_qrhnum);
                    });
                    break;

                case wait_rsp_qrhnum:
                    mProbeStep = step;
                    mProbeTimer.stop();

                    req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__QRHNUM);
                    req.setBodyValue(Xcp.PARAM, localAddress());
                    request(req, (reply) -> {
                        if (!reply.isOk()) {
                            PtLog.e(TAG, "fail!, probe() : wait_rsp_qrhnum");
                            doProbe(ProbeStep.probe_fail);
                            return;
                        }
                        
                        //20210127 단지코드 추가\
                        if (!reply.response().danji().equals("")) setDanji(reply.response().danji());

                        //20210302 자신의 IP와 응답온 IP 비교
                        String rspIp = reply.response().bodyValue("ip");
                        if (rspIp != null) {
                            Log.d(TAG, "qrhnum ip = " + rspIp + " , setting ip = " + OliviaPref.getInstance().get(OliviaPref.ADMIN__NETWORK_IPADDRESS, ""));
                            boolean rs = rspIp.equals(OliviaPref.getInstance().get(OliviaPref.ADMIN__NETWORK_IPADDRESS, ""));
                            if (!rs) {
                                S00_21__mmg_dlg popup = new S00_21__mmg_dlg(getActivity());
                                popup.setTimeout(PtGlobal.NOTICE_POPUP_TIME);
                                popup.setText(getResources().getString(R.string.s11__01_warn_network_input));
                                popup.setButtons(getResources().getString(R.string.s00__ok));
                                S00_20__dlg.showDlg(getActivity(), popup);

                                PtLog.e(TAG, "fail!, probe() : wait_rsp_qrhnum");
                                doProbe(ProbeStep.probe_fail);
                                return;
                            }
                        } else {
                            S00_21__mmg_dlg popup = new S00_21__mmg_dlg(getActivity());
                            popup.setTimeout(PtGlobal.NOTICE_POPUP_TIME);
                            popup.setText(getResources().getString(R.string.s11__01_warn_network_input));
                            popup.setButtons(getResources().getString(R.string.s00__ok));
                            S00_20__dlg.showDlg(getActivity(), popup);

                            PtLog.e(TAG, "fail!, probe() : wait_rsp_qrhnum");
                            doProbe(ProbeStep.probe_fail);
                            return;
                        }

                       String dongho = TextUtils.isEmpty(reply.response().bodyValue(Xcp.DONGHO)) ?
                                reply.response().headerValue(Xcp.DONGHO) : reply.response().bodyValue(Xcp.DONGHO);
                        if (!makeDongHo().equals(dongho)) {
//                    PtLog.e(TAG, "fail!, probe() : verify dongho. expected:, rx:%s", mDong, mHo);
                            PtLog.e(TAG, "fail!, probe() : verify dongho. expected:%s, rx:%s", makeDongHo(), dongho);
                            doProbe(ProbeStep.probe_fail);
                            return;
                        }

                        doProbe(ProbeStep.wait_rsp_install);
                    });
                    break;

                case wait_rsp_install:
                    mProbeStep = step;
                    mProbeTimer.stop();

                    req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__INSTALL);
                    req.setBodyValue("mode", "verchk");
                    request(req, (reply) -> {
                        if (!reply.isOk()) {
                            PtLog.e(TAG, "fail!, probe() : wait_rsp_install");
                            doProbe(ProbeStep.probe_fail);
                            return;
                        }

                        //20210127 단지코드 추가\
                        if (!reply.response().danji().equals("")) setDanji(reply.response().danji());
                        
                        mXcpInstall = reply.response(); // just cache
                        InstallMessage.onReceived(mXcpInstall);
                        doProbe(ProbeStep.wait_rsp_upgrade);
                    });
                    break;

                case wait_rsp_upgrade:
                    mProbeStep = step;
                    mProbeTimer.stop();

                    req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__UPGRADE);
                    req.setBodyValue("unit", "spec");
                    request(req, (reply) -> {
                        if (!reply.isOk()) {
                            PtLog.e(TAG, "fail!, probe() : wait_rsp_upgrade");
                            doProbe(ProbeStep.probe_fail);
                            return;
                        }

                        // begin CJH 2022-07-14 : 중복 처리 제거
//                        mXcpUpgrade = reply.response(); // just cache
//                        on_req_UPGRADE(mXcpUpgrade);
                        // end CJH 2022-07-14
                        if (mConnectionType != ConnectionType.TLS_CERT) doProbe(ProbeStep.probe_success);
                    });
                    break;

                case Idle:
                    mProbeStep = step;
                    mProbeTimer.stop();

                    if (mBroadcastManager != null) {
                        mBroadcastManager.sendBroadcast(new Intent(PhoneInfo.ACTION_XCP_ENGINE_DISCONNECTED));
                    }

                    break;

                case probe_success:
                    mProbeStep = step;
                    mProbeTimer.stop();
                    PtLog.d(TAG, "-----------------");
                    PtLog.d(TAG, "success!, probe()");
                    PtLog.d(TAG, "-----------------");
                    // TODO: 안종윤 (4.20) -  post_proc 없는 것 같음..(upgrade도 하는 것 같음)
                    //PtLog.e(TAG, "TODO: post proc");

                    // 2020-1119 clear pending reply to clear out trash
                    clearPendingReply();

                    // begin kyeongilhan 2021-07-15 : 접속 성공 시 재접속 count 초기화
                    clearMaxConnectRetryCount();
                    // end kyeongilhan 2021-07-15

                    // begin kyeongilhan 2022-07-18 : IoTCertManager 접속 후 열린 단지서버 세션이면 로그 확인해서 ftp로 올린다
                    if (isRenewTried) uploadCertLog();

                    if (mBroadcastManager != null) {
                        mBroadcastManager.sendBroadcast(new Intent(PhoneInfo.ACTION_XCP_ENGINE_CONNECTED));

                        // begin CJH 2022-07-14 : 단지서버 접속 후 업데이트 검사 실시
                            checkNewVersion();
                        // end CJH 2022-02-24
                    }

                    if(mAliveTimer != null) {
                        mAliveTimer.stop();
                        mAliveTimer.setOnTimeoutListener((t) -> req_Q_SERVER());
                        Log.d(TAG, "(Re)Starting target=gateway ALIVE Timer now");
                        // begin kyeongilhan 2021-12-06 : 630초 timer (3.0과 동일한 로직)
                        mAliveTimer.start(TIMEOUT_GATEWAY_ALIVE);
                    }
                    break;

                case probe_fail:
                    mProbeStep = step;
                    if(mAliveTimer != null) {
                        mProbeTimer.stop();
                    }
                    PtLog.e(TAG, "-----------------");
                    PtLog.e(TAG, "fail!, probe()");
                    PtLog.e(TAG, "-----------------");
                    reconnect();
                    PtLog.e(TAG, "after disc");
                    break;

                default:
                    PtLog.e(TAG, "unexpected: %s", step);
            }
        }
    }

    private void uploadCertLog() {
        if (FileLogHelper.getInstance().isCertLogSaved()) {
            Log.e(TAG, "[LOGHELPER] Upload File to Server!");
            Observable<String> observable = FileLogHelper.getInstance().uploadCertManagerLogcat();
            observable.observeOn(Schedulers.io()).subscribe(new Observer<String>() {
                @Override
                public void onSubscribe(@NonNull Disposable d) {

                }

                @Override
                public void onNext(@NonNull String s) {
                    Log.e(TAG, "[LOGHELPER] Upload File Success!");
                }

                @Override
                public void onError(@NonNull Throwable e) {
                    Log.e(TAG, "[LOGHELPER] Upload Logcat Error! " + e.getMessage());
                }

                @Override
                public void onComplete() {

                }
            });
        }
    }

//    void probe_POST() {
        //
        // post process
        //
        /*
            OFCAN
            WEATHER
            LOGINOUT_UPDATE

            download iptable
            download carddb
            download pkg_info.txt
        */
//        async_OFCAN();
//        async_WEATHER_INFO();
//        async_LOGINOUT_UPDATE();        // just request . it cause cmd=30, target=upgrade

        // download iptable
        /*
             INSTALL

             [TX] cmd=10$dongho=101&101$target=install#mode=verchk
             [RX] cmd=11$copy=0-0$dongho=102&9001$target=install#mode=verchk#ver=1.0
             #config_ver=specification.xml
             #iptable_ver=iptable.conf
             #ftpinfo=192.168.13.200,21,gateway,gateway
             #ftp_ip=192.168.13.200
             #ftp_user=gateway
             #ftp_pw=gateway
             #ftp_port=21
             #center_url=http://www.edailybiz.co.kr/ucity/index.html
             #ext_url=
             #help_url=http://10.10.10.10/manual.asp
             #internet_url=http://10.10.10.10/content/internet.asp
             #manual_url=http://10.10.10.10/content/manual.asp
             #rounge_url=http://www.edailybiz.co.kr/ucity/index.html
             #shop_url=http://115.236.165.59/store
             #survey_url=http://10.10.10.10/content/survey.asp
             #weather_url=
        */
//        QUrl url;
//        url.setScheme("ftp");
//        url.setUserName(m_msgInstall.bodyValue("ftp_user"));
//        url.setPassword(m_msgInstall.bodyValue("ftp_pw"));
//        url.setHost(m_msgInstall.bodyValue("ftp_ip"));
//        url.setPort(m_msgInstall.bodyValue("ftp_port").toInt());
//        url.setPath(m_msgInstall.bodyValue("pathname") + "/" + m_msgInstall.bodyValue("iptable_ver"));
//
//        if (m_msgInstall.bodyValue("iptable_ver").isEmpty())
//            PT_LOGW("target=install: iptable_veris EMPTY. skip iptable download \n");
//        else
//            m_ipTableDownloader.get(url, PATH_IPTABLE);
//
//        // download pkginfo
//        LbConf conf;
//        if(conf.value(CK_Version_AutoUpdate). toBool() )
//            doAutoUpdate(m_msgUpgrade);
//    }

//    boolean doAutoUpdate(XcpMessage upgrade)
//    {
//        /*
//            UPGRADE
//
//            [TX] $cmd=10$copy=100-4$dongho=102&9001$target=upgrade#unit=ha
//            [RX] $cmd=11$copy=0-0$target=upgrade#unit=ha
//            #ftpip=192.168.13.200
//            #ftp_ip=192.168.13.200
//            #ftp_port=21
//            #ftp_user=gateway
//            #ftp_pw=gateway
//            #fname=upgrade.script
//            #pathname=/lobby/
//            #swversion=1.0
//            #hwversion=
//            #type=A
//        */
//        QUrl url;
//        url.setScheme("ftp");
//        url.setUserName( upgrade.bodyValue("ftp_user") );
//        url.setPassword( upgrade.bodyValue("ftp_pw") );
//        url.setHost( upgrade.bodyValue("ftp_ip") );
//        url.setPort( upgrade.bodyValue("ftp_port").toInt() );
//        url.setPath( upgrade.bodyValue("pathname") + "/" + upgrade.bodyValue("fname") );
//
//        return LbSwUpdate::instance()->start(url, false);
//    }

    /*
    target=alarm
        issue #1429
        이유가 있습니다만,
        구현하지 마세요. 안하셔도 됩니다.


    target=locationinformation

    target=elevator

    target=doorlock
        issue #1421
        로비폰에서 사용합니다.
        올드 버전에서는 월패드가 target=doorlock 으로 문열림 했습니다. 호환성을 위하여 존재하는 규격 입니다.

        지금은 sip 에서 하는 것으로 알고 있고, 구현하지 마세요.

    target=mp3
        issue #1420
        TDS4.0 에서 필요함

    target=picture
        issue #1419
        TDS4.0 에서 필요함

    target=secsensor
        issue #1418
        1. 방범센서 이벤트 통보 -> 사용됨. ( WP->S )
        2. 방범센서 상태 조회 -> 안해도됨. ( S->WP)
        3. 방범센서 이벤트 통보 -> 안해도됨. (target=secsensor 로 변경됨. "1" 을 사용함. )

    target=gateway
        issue #1417
           (dhlim - 세대 내 케어이벤트(실버케어) 사용시 target=gateway 에서 필드값 1 으로 보냄.)

    target=gateway
        issue #1414

     */
    @Override
    protected void onMessage_ServerRequest(XcpMessage req) {

        if (mProbeStep == ProbeStep.Idle) {
            Log.e(TAG, "Not connected yet.. please wait...");
            return;
        }

        Log.d(TAG, "server request = " + req.target());
/**
    complex_clinet.cpp  ComplexMsgDispatcher[]
*/
        boolean ok = false;
        switch(req.target())
        {
        case Xcp.TARGET__GATEWAY       : /* USED */ ok = on_req_GATEWAY(req); break;
//        case Xcp.TARGET__SERVER        : // UNUSED: only C2S
//        case Xcp.TARGET__INSTALL       : // UNUSED: only C2S
        case Xcp.TARGET__UPGRADE       : /* USED: */ ok = on_req_UPGRADE(req); break;
//        case Xcp.TARGET__QRIP          : // UNUSED: only C2S. sample_req_Q_QRIP
//        case Xcp.TARGET__QRHNUM        : // UNUSED: only C2S. sample_req_Q_QRHNUM
        case Xcp.TARGET__SECSENSOR     : /* USED: */ ok = on_req_SECSENSOR(req); break;
//        case Xcp.TARGET__LOGINOUT      : // UNUSED: only C2S. lobby S2C
//        case Xcp.TARGET__VISITIMAGE_EVENT : // UNUSED: not impl (1050)
//        case Xcp.TARGET__VISITLIST     : // UNUSED: not impl (1050)
//////////////////////////////////////////////////////////////////
//  BEGIN 485
//////////////////////////////////////////////////////////////////
        case Xcp.TARGET__LIGHT         : /* USED: TODO - check */ ok = on_req_LIGHT(req); break;
        case Xcp.TARGET__ALLLIGHT      : /* USED: TODO - check */ ok = on_req_ALLLIGHT(req); break;
        case Xcp.TARGET__BOILER        : /* USED: TODO - check */ ok = on_req_BOILER(req); break;
//        case Xcp.TARGET__MODBUS        : /* UNUSED: not impl (1050) */
        case Xcp.TARGET__AIRFAN        : /* USED: TODO - check */ ok = on_req_AIRFAN(req); break;
            case Xcp.TARGET__GASVALVE      :  /* USED: */ ok = on_req_GASVALVE(req); break;
            case Xcp.TARGET__AIRFAN_OPT    : /* USED: TODO - check */ ok = on_req_AIRFAN_OPT(req); break;
//        case Xcp.TARGET__DOORLOCK      : /* UNUSED: only lobby ( WP는 sip 로 한다.) */
//        case Xcp.TARGET__HOMEMODE      : /* UNUSED: not impl (1050) */
        case Xcp.TARGET__CURTAIN       : /* USED: TODO - check */ ok = on_req_CURTAIN(req); break;
//        case Xcp.TARGET__BATH          : /* UNUSED: not impl (1050) */
        case Xcp.TARGET__STANDBYPWR    : /* USED: TODO - check */ ok = on_req_STDBYPWR(req); break;
        case Xcp.TARGET__SYSCLEIN      : /* USED: */ ok = on_req_ACS(req); break;
        case Xcp.TARGET__AIRCON        : /* USED: TODO - check */ ok = on_req_AIRCON(req); break;
//////////////////////////////////////////////////////////////////
//  END 485
//////////////////////////////////////////////////////////////////
//        case Xcp.TARGET__WEATHER_INFO  : // UNUSED: only C2S. sample_req_Q_WEATHER_INFO
        case Xcp.TARGET__WEATHER_EVENT : /* USED: */ ok = on_req_WEATHER_EVENT(req); break;
//        case Xcp.TARGET__WEATHER_TODAY : // UNUSED: only C2S. sample_req_Q_WEATHER_TODAY
        case Xcp.TARGET__PICTURE       : /* USED: */ ok = on_req_PICTURE(req); break;
        case Xcp.TARGET__MP3           : /* USED: */ ok = on_req_MP3(req); break;
//        case Xcp.TARGET__SMS_TEL       : // UNUSED: only C2S. sample_req_Q_SMS_TEL, sample_req_C_SMS_TEL
//        case Xcp.TARGET__CONTENTS      : // UNUSED: not impl (1050)
//        case Xcp.TARGET__PHONE         : // UNUSED: not impl (1050)
//        case Xcp.TARGET__MANFEE_LIST   : // UNUSED: only C2S. sample_req_Q_MANFEE_LIST
//        case Xcp.TARGET__MANFEE        : // UNUSED: only C2S. sample_req_Q_MANFEE
//        case Xcp.TARGET__OFCAN_LIST    : // UNUSED: only C2S. sample_req_Q_OFCAN_LIST
        case Xcp.TARGET__OFCAN         : /* USED: */ ok = on_req_OFCAN(req); break;
        case Xcp.TARGET__METER         : /* USED: */ ok = on_req_METER(req); break;
        case Xcp.TARGET__METER_INIT    : /* USED: */ ok = on_req_METER_INIT(req); break;
        case Xcp.TARGET__METER_CPS     : /* USED: */ ok = on_req_METER_CPS(req); break;
        case Xcp.TARGET__METERMONTH    : /* USED: */ ok = on_req_METERMONTH(req); break;
//        case Xcp.TARGET__CCTV          : // UNUSED: only C2S. sample_req_Q_CCTV
        case Xcp.TARGET__PARKING       : /* USED: */ ok = on_req_PARKING(req); break;
        case Xcp.TARGET__ELEVATOR      : /* USED: */ ok = on_req_ELEVATOR(req); break;
        case Xcp.TARGET__ROCKER        : /* USED: */ ok = on_req_ROCKER(req); break;
        case Xcp.TARGET__EMERGENCY     : /* USED: */ ok = on_req_EMERGENCY(req); break;
        case Xcp.TARGET__LOCATIONINFO  : /* USED: */ ok = on_req_LOCATIONINFO(req); break;
//        case Xcp.TARGET__ELECTRIC_CAR  : // UNUSED: not impl (1050) -> ELECAR
//        case Xcp.TARGET__SHOP          : // UNUSED: not impl (1050)
//        case Xcp.TARGET__AS            : /* UNUSED: only C2S. sample_req_Q_AS, sample_req_C_AS */
        case Xcp.TARGET__FAMILY_GUARD  : /* USED: */ ok = on_req_FAMILY_GUARD(req); break;
//        case Xcp.TARGET__SURVEY        : // UNUSED: only C2S. sample_req_Q_SURVEY, sample_req_C_SURVEY
//        case Xcp.TARGET__GUARDROOM     : // UNUSED: guard phone. only C2S
//        case Xcp.TARGET__ALARM         : /* UNUSED: guard phone  undoc */
//        case Xcp.TARGET__FIRELOBBY     : // UNUSED: lobby phone.
        /////////////////////////////////////////
        // new
        case Xcp.TARGET__ELECAR        : /* USED: */ ok = on_req_ELECAR(req); break;
//        case Xcp.TARGET__HEALTH        : /* UNUSED: only C2S */
//        case Xcp.TARGET__AIRCONDITION  : /* UNUSED: only C2S */
//        case Xcp.TARGET__AIRCONDITION_EVENT : /* USED: undoc */
        case Xcp.TARGET__DEVICE        : /* USED: */ ok = on_req_DEVICE(req); break;
        default:
            PtLog.e(TAG, "unknown target: '%s'", req.target() );
        }

        if (!ok)
            PtLog.w(TAG, "unhandled target: '%s'", req.target() );
    }


    @Override
    protected void onMessage_UpgradeRequest(XcpMessage req) {
        // override this..
        Log.d(TAG, "server request = " + req.target());
        if(req.target().equals(Xcp.TARGET__UPGRADE)) {
            // begin CJH 2022-07-14 : cmd=11...#unit=spec 여기에서 처리
//            UpgradeMessage.onReceived(req);
            on_req_UPGRADE(req);
            // end CJH 2022-07-14
        }
    }


/*
16 page

#mode=1  : 재실
#mode=11 : 재실( 동물재중 )
#mode=12 : 재실( 테라스 )
    - 테라스 적용 세대의 경우, 외출모드가 아닐경우,월패드에서 적외선 신호 무시 ( 2015-0826)
#mode=2  : 외출
#mode=21 : 외출( 동물재중 )
#mode=3  : 취침
#mode=31 : 취침( 동물재중 )
#mode=4  : 재실 ( 테라스 )
*/

/*
            enum SecurityMode {
                SM_InHome = 1,
    // ezVille-chang begin 20151120:
                SM_TerraceAndInHome = 12,
    //...
                SM_OutDoor = 2,
                SM_Sleep = 3,
                SM_PetAndInHome = 11,
                SM_PetAndOutDoor = 21,
                SM_PetAndSleep = 31,
            };
 */
    /**
     * copy from ehw-1050
     */

    /*
    mode
        #mode=1 : 재실
        #mode=11 : 재실( 동물재중 )
        #mode=12 : 재실( 테라스 )
            - 테라스 적용 세대의 경우, 외출모드가 아닐 경우,월패드에서 적외선 신호 무시 ( 2015-0826)
        #mode=2 : 외출
        #mode=21 : 외출( 동물재중 )
        #mode=3 : 취침
        #mode=31 : 취침( 동물재중 )
        #mode=4 : 재실 ( 테라스 )

    mode_user
        #mode_user
        #mode_user=0 : 출동경비
        #mode_user=1 : 사용자
        #mode_user=2 : 기타
        #mode_user=3 : 매직미러

    mode_user
        #mode_method=10: 마스터 비밀번호 무장설정,해제
        #mode_method=11: 세대 비밀번호 1 무장설정,해제
        #mode_method=12: 세대 비밀번호 2 무장설정,해제
        #mode_method=13: 세대 비밀번호 3 무장설정,해제
        #mode_method=14: 세대 비밀번호 4 무장설정,해제
        #mode_method=20: 마스터 카드 무장 설정,해제
        #mode_method=21: 세대 카드 1 무장 설정,해제
        #mode_method=22: 세대 카드 2 무장 설정,해제
        #mode_method=23: 세대 카드 3 무장 설정,해제
        #mode_method=24: 세대 카드 4 무장 설정,해제
        #mode_method=25: 세대 카드 5 무장 설정,해제
        #mode_method=26: 세대 카드 6 무장 설정,해제
        #mode_method=27: 세대 카드 7 무장 설정,해제
        #mode_method=28: 세대 카드 8 무장 설정,해제
        #mode_method=30 :매직미러 무장,설정,해제
    */
    boolean on_req_GATEWAY(XcpMessage req)
    {
        // test
//        Intent intent = new Intent(mContext, com.olivia.homesvr.s02_device.S02_main.class);
//        String uri = new Uri.Builder()
//                .appendQueryParameter("cmd", "xcp")
//                .toString()
//                ;
//        intent.putExtra("uri", uri );
//        mContext.startActivity(intent);
        //...

        try {
            if( req.is_QUERY_REQ() ) {
            /*
                1. 홈 서버 상태 정보 조회(초기 접속
                - 요청 (단지서버 -> 클라이언트 )
                <start=0000&0>$version=2.0$copy=00-0000$cmd=10$target=gateway

                - 응답 (클라이언트 -> 단지서버 )
                <start=0000&0>$version=2.0$copy=00-0000$cmd=11$target=gateway
                #dongho=101&101
                #ip=123.0.0.0
                #status=0
                #curtime=20070101120000
                #hwversion=1.0
                #swversion=1.1
                #mode=1
                #mode_user=0
                #alarm=1&20070101120000

                5. 홈 서버의 상태를 단지서버가 조회를 함.(확장버전) 위와 동일.
            */
                XcpMessage rsp = newResponse(req);
                if(rsp != null ) {
                    rsp.setBodyValue(Xcp.DONGHO, String.format(Locale.US, "%d&%d", getDong(), getHo()));
                    rsp.setBodyValue(Xcp.IP, localAddress());
                    // 220211 CJH 'status' 는 0 으로 고정
                    rsp.setBodyValue(Xcp.STATUS, "0");    // fix: 세대상태 : 0 정상
                    rsp.setBodyValue(Xcp.CURTIME, PtDateTime.current().toString("yyyyMMddHHmmss"));

                    if (mConnectionType == ConnectionType.TLS_CERT) rsp.setBodyValue(Xcp.HWVERSION, "NoCert_"+getMacAddress());
                    else if (mConnectionType == ConnectionType.TLS_TEMP) {
                        CertManager certManager = CertManager.getInstance();
                        String errorCode = OliviaPref.getInstance().getAsciiString(ADMIN__CERTMANAGER_ERROR_CODE, "");
                        if (errorCode == null) rsp.setBodyValue(Xcp.HWVERSION, "Temp_" + getMacAddress() + "_" +
                                + certManager.getTempCertExpireDueDates(getApplicationContext()));
                        else if (errorCode.equals("")) rsp.setBodyValue(Xcp.HWVERSION, "Temp_" + getMacAddress() + "_" +
                                + certManager.getTempCertExpireDueDates(getApplicationContext()));
                        else rsp.setBodyValue(Xcp.HWVERSION, "Temp_" + getMacAddress() + "_" + errorCode + "_"
                                    + certManager.getTempCertExpireDueDates(getApplicationContext()));
//                    rsp.setBodyValue(Xcp.HWVERSION, "Temp_" + getMacAddress() + "_" + (errorCode.equals("") ? "" : errorCode) + "_"
//                            + certManager.getTempCertExpireDueDates(getApplicationContext()));
                    }
                    else if (mConnectionType == ConnectionType.TLS) {
                        CertManager certManager = CertManager.getInstance();
                        String errorCode = OliviaPref.getInstance().getAsciiString(ADMIN__CERTMANAGER_ERROR_CODE, "");
                        if(certManager.isPfxCertDueToExpire(getApplicationContext())) {
                            if (errorCode == null) rsp.setBodyValue(Xcp.HWVERSION, "Renew_" + getMacAddress() + "_" + certManager.getH1(getApplicationContext())
                                    + "_" + certManager.getCertExpireDueDates(getApplicationContext()));
                            else if (errorCode.equals("")) rsp.setBodyValue(Xcp.HWVERSION, "Renew_" + getMacAddress() + "_" + certManager.getH1(getApplicationContext())
                                    + "_" + certManager.getCertExpireDueDates(getApplicationContext()));
                            else rsp.setBodyValue(Xcp.HWVERSION, "Renew_" + getMacAddress() + "_" + certManager.getH1(getApplicationContext())
                                        + "_" + errorCode + "_" + certManager.getCertExpireDueDates(getApplicationContext()));
                        }
                        else rsp.setBodyValue(Xcp.HWVERSION, getMacAddress());
                    }
                    else rsp.setBodyValue(Xcp.HWVERSION, getMacAddress());

                    rsp.setBodyValue(Xcp.SWVERSION, BuildConfig.VERSION_NAME);
                    // begin CJH 2022-07-11 : target=gateway 응답 시 스펙 버전 추가
                    rsp.setBodyValue(Xcp.SPECVERSION, getSpecificationVersion());
                    // end CJH 2022-07-11
                    // begin kyeongilhan 2022-09-27 : spectype 추가
                    rsp.setBodyValue(Xcp.SPECTYPE, getSpecificationType());
                    // end kyeongilhan 2022-09-27

                    rsp.setBodyValue(Xcp.MODE, OliviaPref.getCurrentHomeMode());
                    rsp.setBodyValue(Xcp.MODE_USER, "1"); // user
                    rsp.setBodyValue(Xcp.MODE_METHOD, OliviaPref.getUserModeMethod());
                    rsp.setBodyValue(Xcp.ALARM, "0&" + PtDateTime.current().toString("yyyyMMddHHmmss")); // QDBusClientInfo_GetRecentAlarm, QDBusClientInfo_GetAlarmTime
                    // 220520 CJH 안심케어 Enable
                    // 220211 CJH 안심케어 데이터 필드 추가
                    // 사용   -> "rcare=on"
                    // 미사용 -> "rcare=off"
                    rsp.setBodyValue(Xcp.RCARE, OliviaPref.getSilverCareAcivate() ? "on" : "off");

                    if (mProbeStep == ProbeStep.wait_req_gateway) {
                        mXcpGateway = req;
                        if (mProbeTimer != null) mProbeTimer.stop();
                        if (req.bodyValue("partner").isEmpty()) { // plain
                            PtLog.i(TAG, "PLAIN mode");
                            sendMessage(rsp);
                        } else { // encrypt
                            PtLog.e(TAG, "------[AES ENCRYPT mode]------");
                            // make 16 byte key.
                            mKey = AesEngine.getRandomString(16).getBytes();

                            String encodedKey =  null;
                            try {
                                //encodedKey = Base64.encodeToString(AesEngine.encrypt("j2u3s4t5d6o7i8t9".getBytes(), mKey), Base64.DEFAULT);
                                encodedKey = Base64.encodeToString(AesEngine.encrypt(mContext.getString(R.string.aes_key).getBytes(), mKey), Base64.DEFAULT);
                            } catch (Exception e) {
                                e.printStackTrace();
                                return false;
                            }
                            //                PtLog.i(TAG, "buf[]:%s", Arrays.toString(key) );
                            PtLog.i(TAG, "-------------------------");
                            PtLog.i(TAG, "rand[]:%s", encodedKey);
                            PtLog.i(TAG, "-------------------------");
                            rsp.setBodyValue(Xcp.KEY, encodedKey);

                            sendMessageAesInit(rsp);
                        }

                        if (mConnectionType != ConnectionType.TLS_CERT) doProbe(ProbeStep.wait_rsp_server);
                        else doProbe(ProbeStep.wait_rsp_upgrade);


                        return true;
                    } else {

                        if (mAliveTimer != null) {
                            Log.e(TAG, "Received target=gateway.. set timer refresh");
                            mAliveTimer.stop();
                            mAliveTimer.setOnTimeoutListener((t) -> req_Q_SERVER());
                            Log.e(TAG, "(Re)Starting target=gateway ALIVE Timer now");
                            // begin kyeongilhan 2021-12-06 : 630초 timer (3.0과 동일한 로직)
                            mAliveTimer.start(TIMEOUT_GATEWAY_ALIVE);
                        }

                        if (!req.bodyValue("partner").isEmpty()) { // plain
                            if (mKey == null) {
                                PtLog.e(TAG, "------[AES ENCRYPT mode]------");
                                // make 16 byte key.
                                mKey = AesEngine.getRandomString(16).getBytes();

                                String encodedKey = null;
                                try {
                                    encodedKey = Base64.encodeToString(AesEngine.encrypt("j2u3s4t5d6o7i8t9".getBytes(), mKey), Base64.DEFAULT);
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    return false;
                                }
                                //                PtLog.i(TAG, "buf[]:%s", Arrays.toString(key) );
                                PtLog.i(TAG, "-------------------------");
                                PtLog.i(TAG, "rand[]:%s", encodedKey);
                                PtLog.i(TAG, "-------------------------");
                                rsp.setBodyValue(Xcp.KEY, encodedKey);

                                sendMessageAesInit(rsp);
                                return true;
                            }
                        }


                        return sendMessage(rsp);
                    }
                }
            }
            else if( req.is_CTRL_REQ() || req.is_EVENT_REQ() || req.is_EVENT_REQ()) {
                return GatewayMessage.onReceived(getApplicationContext(),
                        req);
            }
            return false;
        } catch (Exception e) {
            return false;
        }

    }

    public ProbeStep getProbeStep() {
        return mProbeStep;
    }

    public void req_Q_SERVER() {
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__SERVER);
		boolean ok = request(req, (reply)->{
		    if ( reply.isOk() ) {
                on_rsp_SERVER(reply.response());
            }
		    else {
                Log.e(TAG, "Alive Timer response failed..");
                reconnect();
            }
        });

        if(!ok) {
            Log.e(TAG, "Alive Timer failed..");
            reconnect();
        }
	}

    boolean on_rsp_SERVER(XcpMessage rsp)
    {
        if ( mDebugMsg ) PtLog.i(TAG, "on_rsp_XXX(): %s", rsp.toSummary() );

        if( rsp.is_QUERY_RSP() ) {
            /**
                <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=server
                #ip=10.10.10.10
                #curtime=20090225123000
            */

            //20210127 단지코드 추가\
            if (!rsp.danji().equals("")) setDanji(rsp.danji());

            PtDateTime serverTime = new PtDateTime(rsp.bodyValue("curtime"), "yyyyMMddHHmmss");
            if (!serverTime.isValid()) {
                PtLog.e(TAG, "invalid serverTime:%s", rsp.bodyValue("curtime"));
                return false;
            }

            PtDateTime clientTime = PtDateTime.current();
            long diff = Math.abs(serverTime.getTime() - clientTime.getTime());
            if (diff > 5000) { // 5 sec

                mAliveTimer.stop();

                PtLog.e(TAG, "diff 5sec svr:%s, cli:%s"
                    , serverTime.toString("yyyy-MM-dd HH:mm:ss")
                    , clientTime.toString("yyyy-MM-dd HH:mm:ss")
                );

                // you must use AlarmManager class
                if(!PhoneInfo.isEmulator()) {
                    final Calendar c = Calendar.getInstance();
                    c.setTimeInMillis(serverTime.getTime());
                    AlarmManager alarmManager = (AlarmManager) mContext.getSystemService(ALARM_SERVICE);
                    alarmManager.setTime(c.getTimeInMillis());
                }

                ServerMessage.onReceived(rsp);
            }

            //if ( !mAliveTimer.isActive() ) {
            if (mAliveTimer != null) {
                mAliveTimer.setOnTimeoutListener((t) -> req_Q_SERVER() );
                Log.e(TAG, "(Re)Starting target=gateway ALIVE Timer now");
                // begin kyeongilhan 2021-12-06 : 630초 timer (3.0과 동일한 로직)
                mAliveTimer.start(TIMEOUT_GATEWAY_ALIVE);
            }

            //}

            return true;
        }
        return false;
    }

    boolean on_req_UPGRADE(XcpMessage req) {

        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );

        if ( req.is_CTRL_REQ() || req.is_QUERY_RSP() ) {
            /*
                2. 업그레이드 요청
                - 요청 (단지서버 -> 홈 서버 )Service
                <start=0000&0>&version=2.0$cmd=20$dongho=101&101$target=upgrade
                #unit=ha
                #ftpip=100.0.0.2#ftp_user=qwe#ftp_pw=1234#ftp_port=21
                #fname=hafa-release-050521.bin
                #pathname=abc
                #hwversion=ver2.0.1
                #hwversion=ver3.0.1

                - 응답 (홈 서버 -> 단지서버 )
                <start=0000&0>$version=2.0$cmd=21$dongho=101&101$target=upgrade
                #unit=ha

                - 에러 (홈 서버 -> 단지서버 )
                <start=0000&0>$version=2.0$cmd=21$dongho=101&101$target=upgrade
                #unnit=ha#err=0001&업그레이드실패
            */

            //20210127 단지코드 추가
            if (!req.danji().equals("")) setDanji(req.danji());
            
            UpgradeEvent event = new UpgradeEvent(req);
            if(!event.error.isEmpty()) {
                Log.e(TAG, "upgrade failed; " + event.error);
                return false;
            }

            OliviaPref pref = OliviaPref.getInstance();
            boolean isSpecUpdate = false;
            boolean isCertDownloadPort = (mConnectionType == ConnectionType.TLS_CERT);
            boolean isTempCert = (mConnectionType == ConnectionType.TLS_TEMP);

            if(event.unit.equals("spec")) {

                if (!TextUtils.isEmpty(event.sw_version))
                    pref.put(OliviaPref.ADMIN__SPEC_VERSION, event.sw_version);

                if (!TextUtils.isEmpty(event.file_name))
                    pref.put(OliviaPref.ADMIN__SPEC_FILENAME, event.file_name);

                if (!TextUtils.isEmpty(event.file_path))
                    pref.put(OliviaPref.ADMIN__SPEC_DOWNPATH, event.file_path);

                if(sXmlSpec.m_version.equals(event.sw_version)) {
                    // 220308 CJH "unit=spec" 에러 메시지 추가
                    if(req.is_CTRL_REQ()) {
                        sendSpecUpdateResponse(req.copy(), Xcp.ERR__UPDATE_DOWNGRADE);
                    }

                    if (!isCertDownloadPort) {
                        if (!isTempCert) {
                            Log.e(TAG, "same version exists.. no need to update");
                            return true;
                        }
                    }
                }
                else {
                    Log.d(TAG, "need to update specification data");
                    //sXmlSpec.m_apartment_type = event.apt_type;
                    if (!isCertDownloadPort) isSpecUpdate = true;
                    if (!TextUtils.isEmpty(event.apt_type))
                        pref.put(OliviaPref.ADMIN__APT_TYPE, event.apt_type);
                }

                int port = 21; //default port
                try {
                    port = Integer.parseInt(event.ftp_port);
                }
                catch(NumberFormatException e) {
                    Log.e(TAG, e.getMessage());
                }

                if (isSpecUpdate) {
                    // 220714 CJH 스펙 업데이트 중에 런처 업데이트를 막기 위해 flag 설정
                    PhoneInfo.mPhoneIsUpdating = true;
                    downloadAndSaveSpecification(event.getCmd().equals(Xcp.CMD__CTRL_REQ) ? event.getCopy() : "",
                            event.ftp_ip,
                            port,
                            event.ftp_user,
                            event.ftp_pwd,
                            event.file_path + "/" + event.file_name,
                            "specification_new.xml",
                            sXmlSpec.m_version,
                            event.sw_version);
                }

                // 20210512 35100 포트이면 인증서 다운로드 위해 접속 한다
                // 먼저 자신의 MAC 주소로 된 인증서를 찾고
                // 없으면 temp.pfx 를 찾고
                // 그것도 없으면 끝 내고 다시 doProbe 한다
               if (isCertDownloadPort) {
                   downloadAndSaveCertification(event.getCmd(),
                           event.ftp_ip,
                           port,
                           event.ftp_user,
                           event.ftp_pwd,
                           getMacAddress()+".pfx");
                }

               /*if (isTempCert) {
                   downloadAndSaveMyCertification(event.getCmd(),
                           event.ftp_ip,
                           port,
                           event.ftp_user,
                           event.ftp_pwd,
                           getMacAddress()+".pfx");
               }
*/
                return true;
            }

            return UpgradeMessage.onReceived(req);
        }
        return false;
    }

    public boolean sample_req_Q_QRIP(String dong, String ho) {
        /*
        1. 아이피 조회

        - 요청(홈 서버->단지서버 )
        <start=000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=qrip
        #param=101&405

        - 응답(단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrip
        #dongho=101&405#ip=10.4.1.2

        - 에러(단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrip
        #err=0001&아이피를 찾을 수 없습니다.


        1_1. 아이피 조회( 세대 아이피 조회시 외출 여부 확인, 2016 년 6 월 이후 현장)
        - 요청(홈 서버->단지서버 )
        <start=000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=qrip
        #param=101&405

        - 응답(단지서버 -> 홈 서버 : 외출 아닐 경우 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrip
        #dongho=101&405#ip=10.4.1.2#comment=세대

        - 응답(단지서버 -> 홈 서버 : 외출일 경우 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrip
        #dongho=101&405#ip=10.4.1.2#err=0002&outdoors

         */
        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__QRIP);
		req.setBodyValue("param", dong + "&" + ho );
		return request(req, (reply)-> {
            if ( !reply.isOk() )
		        return;

            XcpMessage rsp = reply.response();
            String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // do something with err
                return;
            }

            String ip = rsp.bodyValue("ip");
            String comment = rsp.bodyValue("comment"); // 2016 년 6 월 이후 현장
            //  do something
        });
    }

    /**
     *
     * @param dname
     *    #param=parking :주차서버
     *    #param=door:공동현관기
     *    #param=guard:경비실기
     *    #param=man: 관리실
     *    #param=elevator :엘리베이터 서버
     *    #param=locker :택배
     *    #param=homecare: 홈케어
     *    #param=xi_center : 자이안센터
     *    #param=driver_room : 기사대기실
     *    #param=housekeeper_room : 도우미대기실
     *    #param=delivery_room : 택배실
     *    #param=concierge : 컨시어져
     * @return
     */
    public boolean sample_req_Q_QRIP_device(String dname) {
        /*
        3. 특수 세대 아이피 조회(홈케어 등 특수 세대 )
        - 요청 (홈 서버 ->단지서버 )
        <start=000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=qrip
        #mode=device#param=homecare

        - 응답(단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrip
        #mode=device#param=homecare#dongho=400&114#ip=10.4.1.2

        - 에러(홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrip
        #mode=device#err=0001&아이피를 찾을 수 없습니다.
         */
        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__QRIP);
		req.setBodyValue("mode", "device");
		req.setBodyValue("param", dname );
		return request(req, (reply)-> {
            if ( !reply.isOk() )
		        return;

            XcpMessage rsp = reply.response();
            String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // do something with err
                return;
            }

            String dongho  = rsp.bodyValue("dongho");
            String ip = rsp.bodyValue("ip");
            // do something
        });
    }

    /**
     *
     * @param dname  "outdoor" only supported
     * @param start
     * @param end
     * @return
     */
    public boolean sample_req_Q_QRIP_device2(String dname, int start, int end) {
        /*
        3_1. 특수 세대 아이피 조회(홈케어 등 특수 세대가 여러 세대일 경우)
        - 요청 (홈 서버 ->단지서버 )
        <start=000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=qrip
        #mode=device2
        #dname=outdoor
        #param=1&5

        - 응답(단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrip
        #mode=device2
        #dname=outdoor
        #cnt=2
        #list=101&9001&10.101.0.9&옥상개폐기,101&9002&10.101.0.19&옥상개폐기

        - 에러(홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrip
        #mode=device2
        #dname=outdoor
        #err=0001&NO_DATA.
         */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__QRIP);
		req.setBodyValue("mode", "device2");
		req.setBodyValue("dname", dname);
		req.setBodyValue("param", Xcp.make_range(start, end) );
		return request(req, (reply)-> {
            if ( !reply.isOk() )
		        return;

            XcpMessage rsp = reply.response();
            String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // do something with err
                return;
            }
            String lcnt  = rsp.bodyValue("cnt");
            String list = rsp.bodyValue("list");
//                String[] dlist = StringUtils.split(list, ',');
//                do something with dlist
        });
	}

    public boolean sample_Q_QRHNUM(String ip)
    {
        /*
        1. 동,호수 아이피 조회.
        - 요청( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=qrhnum
        #param=10.2.2.2

        - 응답( 단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrhnum
        #dongho=101&405#ip=10.4.1.2

        - 에러( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrhnum
        #err=0001&동호수 정보를 찾을 수 없습니다.

        1_1. 동,호수 아이피 조회.
        - 요청( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$copy=00-
        0000$cmd=10$dongho=101&201$target=qrhnum#param=10.2.2.2
        - 응답( 단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrhnum
        #dongho=101&405
        #ip=10.4.1.2
        #comment=세대
        - 에러( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrhnum
        #err=0001&동호수 정보를 찾을 수 없습니다.
         */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__QRHNUM);
		req.setBodyValue("param", ip);
		return request(req, (reply)-> {
            if ( !reply.isOk() )
		        return;

            XcpMessage rsp = reply.response();
            String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                 // do something with err
                return;
            }

            String dongho  = rsp.bodyValue("dongho");
            String comment = rsp.bodyValue("comment");
            // do something
        });
    }

    /**
     *
     * @param dname
     *    #param=parking :주차서버
     *    #param=door:공동현관기
     *    #param=guard:경비실기
     *    #param=man: 관리실
     *    #param=elevator :엘리베이터 서버
     *    #param=locker :택배
     *    #param=homecare: 홈케어
     *    #param=xi_center : 자이안센터
     *    #param=driver_room : 기사대기실
     *    #param=housekeeper_room : 도우미대기실
     *    #param=delivery_room : 택배실
     * @return
     */
    public boolean sample_Q_QRHNUM_device(String dname)
    {
        /*
        2. 동,호수 아이피 조회(mode=device)
        - 요청( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&100$target=qrhnum
        #param=10.2.2.2

        - 응답( 단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrhnum
        #mode=device
        #param=homecare
        #dongho=400&114
        #ip=10.4.1.2

        - 에러( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=qrhnum
        #err=0001&동호수 정보를 찾을 수 없습니다
         */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__QRHNUM);
		req.setBodyValue("mode", "device");
		req.setBodyValue("param", dname);
		return request(req, (reply)-> {
            if ( !reply.isOk() )
		        return;

            XcpMessage rsp = reply.response();
            String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // do something with err
                return;
            }

            String dongho  = rsp.bodyValue("dongho");
            String comment = rsp.bodyValue("comment");
            // do something
        });
    }

    /**
     *
     * @param no
     *  #no=1 : 화재
     *  #no=2 : 방범
     *  #no=3 : 가스
     *  #no=4 : 비상
     *  #no=5 : make up room
     *  #no=6 : Do not disturb
     *  #no=7 : 공용 화재 신호
     *  #no=8 : 외출
     *  #no=9 : 외출(동물)
     *  #no=10 : 취침
     *  #no=11: 취침(동물)
     *  #no=12: 재실
     *  #no=13:단선
     * @return
     */
    public boolean sample_req_E_SECSENSOR(int no) {
        /**
         * issue #1418
         * Q1) "1. 방범센서 이벤트 통보" 현재 사용되는 건가요? (월패드)
         * => 네
         */
        /*
        1. 방범센서 이벤트 통보
        - 통보( 홈 서버->단지서버->경비실)
        <start=0000&0>$version=2.0$copy=00-0000$cmd=30$dongho=101&201$target=secsensor
        #mode=2#no=1#onoff=1#alarm=1#zone=2#dongho=101&201
        - 응답( 경비실,HNMC -> 단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&201$target=secsensor

        Make up room / do not distrub 이벤트 통보
        - 통보( 홈 서버->단지서버)
        <start=0000&0>$version=2.0$copy=00-0000$cmd=30$dongho=101&201$target=secsensor
        #mode=1#no=5#onoff=1#alarm=1#zone=2#dongho=101&201
        - 응답(단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$copy=00-
        0000$cmd=31$dongho=101&201$target=secsensor#mode=1#no=5#onoff=1#zone=2
        */
        XcpMessage req = newRequest(Xcp.CMD__EVENT_REQ, Xcp.TARGET__SECSENSOR);
        req.setBodyValue("mode", OliviaPref.getCurrentHomeMode() );
        req.setBodyValue("no", no);
        req.setBodyValue("onoff", "1"); // 0:normal, 1:abnormal
        req.setBodyValue("alarm", "1");
        req.setBodyValue("zone", "1");
        req.setBodyValue("dongho", makeDongHo());
        return request(req);
    }

    boolean on_req_SECSENSOR(XcpMessage req) {

        if ( req.is_QUERY_REQ() ) {
            /**
             * issue #1418
             * Q2) "2. 방범센서 상태 조회" 현재 사용되는 건가요? (월패드)
             * EHW1050 문서와 다르게 구현되어 있는것으로 보아, 사용 안하는 것 같음.
             *
             * => 당사 월패드 개발자들이 상태조회 불가하다고 했었습니다.
             * => 오랜 과거에는 사용했었습니다만, 1050에 구현되어 있지 않으면 안해도 될 것 같습니다.
             */
            /*
            2. 방범센서 상태 조회
            - 통보( 단지서버 -> 홈 서버 )
            <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=secsensor

            - 응답( 홈 서버 -> 단지서버 )
            <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=secsensor
            #no=1#onoff=1#alarm=0
            #no=2#onoff=1#alarm=0
            #no=3#onoff=1#alarm=0
            #no=4#onoff=1#alarm=0

            - 에러
            <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=secsensor
            #err=0001&센서감지오류
             */
            return false;
        }
        else if ( req.is_EVENT_REQ() ) {
            /**
             * issue #1418
             * Q3) "3. 세대 내 케어 이벤트 통보" section=care 수신시, 월패드는 어떤 동작을 해야 하나요?
             * => 사용하지 않으셔도 됩니다. target=secsensor로 변경되었습니다.
             * => target=secsensor#section=care 으로 응답. (담당자 변경되어 응답 해야하는 것으로 보임)
             */
            return SecuritySensorMessage.onReceived(req);
        }
        return false;
    }


    /**
     * 로비폰에서만 사용.
     *  authentivate
     *  add
     *  remove
     *
     * 3) EHW1050 : type=3 사용
     *
     * #type=1 : 카드 키 인증
     * #type=2 : 마스터키 인증( 스마트키 )
     * #type=3 : 비밀번호 인증
     * #type=4 : 세대비밀번호 인증( 월패드 연동)
     *
     * @return
     */
    public boolean sample_req_C_LOGINOUT() {
        /*
        1. 카드 정보 추가
        - 요청 (월패드-> 단지서버 )
        <start=0000&0>$version=2.0$cmd=20$copy=00-
        0000$dongho=101&201$target=loginout#mode=add#cnt=1#data=101,201,1,1111BCAAA
         */
        XcpMessage req = newRequest(Xcp.CMD__CTRL_REQ, Xcp.TARGET__LOGINOUT);
//		req.setBodyValue("param", dong + "&" + ho );
//		return request(req, (reply)-> {
//            if ( !reply.isOk() )
//		        return;
//
//            XcpMessage rsp = reply.response();
//            String err = reply.response().bodyValue("err");
//            if ( !err.isEmpty() ) {
//                // do something with err
//                return;
//            }
//
//            String ip = rsp.bodyValue("ip");
//            String comment = rsp.bodyValue("comment"); // 2016 년 6 월 이후 현장
//            //  do something
//        });
        return false;
    }

    boolean on_req_LIGHT(XcpMessage req) {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
        return DevLightMessage.onReceived(XcpEngine.this, req);
    }

    boolean on_req_ALLLIGHT(XcpMessage req) {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
        return DevBatchBreakerMessage.onReceived(XcpEngine.this, req);
    }

    boolean on_req_BOILER(XcpMessage req)  {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
        return DevBoilerMessage.onReceived(XcpEngine.this, req);
    }

    boolean on_req_GASVALVE(XcpMessage req)
    {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
        return DevGasValveMessage.onReceived(XcpEngine.this, req);
    }

    boolean on_req_AIRFAN(XcpMessage req) {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
        return DevVentilatorMessage.onReceived(XcpEngine.this, req);
    }

    boolean on_req_AIRFAN_OPT(XcpMessage req) {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
        return DevVentilatorMessage.onReceived(XcpEngine.this, req);
    }

    boolean on_req_CURTAIN(XcpMessage req) {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
        return DevCurtainMessage.onReceived(XcpEngine.this, req);
    }

    boolean on_req_STDBYPWR(XcpMessage req)  {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
        return DevStandbyPowerMessage.onReceived(XcpEngine.this, req);
    }

    boolean on_req_AIRCON(XcpMessage req)  {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
        return DevAirConditionerMessage.onReceived(XcpEngine.this, req);
    }

    boolean on_req_ACS(XcpMessage req)  {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
//        return DevSysCleinMessage.onReceived(XcpEngine.this, req);
        return DevSysCleinMessage.getInstance().onReceived(XcpEngine.this, req);
    }

    public boolean sample_req_Q_WEATHER_INFO() {
        /*
        1. 날씨 정보 조회
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-000$cmd=10$dongho=101&201$target=weather_info

        - 조회 응답
        <start=0293&0>$version=2.0$cmd=11$copy=0-0$dongho=204&2504$target=weather_info
        #day1_low=14.0
        #day1_hi=27.0
        #day1_cur_temp=19.0
        #day1_time=20110528090000
        #day1_day=28
        #day1_temp=19.0
        #day1_icon=03
        #day1_opt=0.030,10
        #day2_day=29
        #day2_low=16.0
        #day2_hi=28.0
        #day2_icon=01
        #day2_opt=0.030,10
        #day3_day=30
        #day3_low=15.0
        #day3_hi=27.0
        #day3_icon=03
        #day31_opt=0.030,10

        - 에러
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=weather_info
        #err=0001&날씨정보가 없습니다.
        */
        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__WEATHER_INFO);
        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error

            // do something
            rsp.bodyValue("day1_low");
            rsp.bodyValue("day1_high");
            rsp.bodyValue("day1_cur_temp");
            // ...
        });
    }

    public boolean sample_req_Q_WEATHER_INFO(String city) {
    /*
    2. 날씨 정보 조회 (Google Weather 사용)
    - 조회 요청
    <start=0000&0>$version=2.0$copy=00-000$cmd=10$dongho=101&201$target=weather_info
    #mode=google#city=shanghai

    - 조회 응답
    <start=0000&0>$version=2.0$copy=00-
    000$cmd=11$dongho=101&201$target=weather_info#mode=google#city=shanghai
    #day1_low=1.0
    #day1_hi=10
    #day1_cur_temp=5
    #day1_time=20070328121212
    #day1_day=25
    #day1_temp=10
    #day1_icon=99
    #day1_icon_image=/ig/images/weather/cloudy.gif
    #day2_day=26
    #day2_temp=8
    #day2_icon=99
    #day2_icon_image=/ig/images/weather/cloudy.gif
    #day3_day=27#day3_temp=11#day3_icon=99
    #day3_icon_image=/ig/images/weather/cloudy.gif

    - 에러
    <start=0000&0>$version=2.0$copy=00-
    0000$cmd=11$dongho=101&201$target=weather_info#mode=google
    #city=shanghai#err=0001&날씨정보가 없습니다
     */
        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__WEATHER_INFO);
        req.setBodyValue("mode", "google");
        req.setBodyValue("city", "city");
        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error

            // do something
            rsp.bodyValue("day1_low");
            rsp.bodyValue("day1_high");
            rsp.bodyValue("day1_cur_temp");
            // ...
        });
    }

    boolean on_req_WEATHER_EVENT(XcpMessage req)
    {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );
        if ( req.is_EVENT_REQ() ) {
            return WeatherMessage.onReceived(req);
        }
        return false;
    }

    public boolean sample_req_Q_WEATHER_TODAY() {
    /*
    4. 날씨 정보 조회(메인)
    - 조회 요청
    <start=000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=weather_today

    - 조회 응답
    <start=000&0>$version=2.0$copy=00-
    0000$cmd=11$dongho=101&201$target=weather_today
    #weathericon=01
    #temperature=20
    #day_opt=0.030,강수량
    주) 3 일 예보상의 미세먼지 정보를 오늘의 날씨에 붙여서 보내는 것임을 유의해야 함.
     */
        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__WEATHER_TODAY);
        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error

            // do something
            rsp.bodyValue("weathericon");
            rsp.bodyValue("temperature");
            rsp.bodyValue("day_opt");
            // ...
        });
    }

    private static final String PICTURE_PATH = Environment.getExternalStorageDirectory()+"/picture";
    private static final String MP3_PATH = Environment.getExternalStorageDirectory()+"/mp3";

    boolean on_req_PICTURE(XcpMessage req)  {

        if ( req.is_QUERY_REQ() ) {

            /*
            1. 액자이미지 파일 조회
            - 조회 요청
            <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=picture

            - 조회 응답(전체 액자 리스트 조회 )
            <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=picture
            #no=1#url=#use=1#filename=aaa.jpg
            #no=2#url=#use=0#filename=bbb.jpg

            - 에러
            <start=0000&0>$version=2.0$copy=00-
            0000$cmd=11$dongho=101&201$target=picture#err=0001&이미지가 존재하지 않습니다.
             */

            XcpMessage rsp = newResponse(req);
            File path = new File(PICTURE_PATH);
            String[] files = path.list(new FilenameFilter(){
                public boolean accept(File dir, String name) {
                    return name.endsWith(".jpg") || name.endsWith(".jpeg") || name.endsWith(".png");
                }
            });

            if ( files == null || files.length == 0 ) {
                rsp.setBodyValue("err", "0001&이미지가 존재하지 않습니다.");
                sendMessage(rsp);
                return true;
            }

            for(int i = 0 ; i < files.length ; ++i) {
                rsp.setBodyValue("no", i+1);
                rsp.setBodyValue("url", "");
                rsp.setBodyValue("use", 0);
                rsp.setBodyValue("filename", files[i]);
            }
            return sendMessage(rsp);
        }
        else if ( req.is_CTRL_REQ() ) {
            String mode = req.bodyValue("mode");
            if ( mode == "upload") {

            }
            else if ( mode == "delete") {

            }
            else if ( mode == "update") {
// need activity
//                Intent intent = new Intent();
//                startActivityForResult()
            }
            else {
                XcpMessage rsp = newResponse(req);
                rsp.setBodyValue("mode", mode);
                rsp.setBodyValue("err", "0001& 명령어가 처리되지 않았습니다.");
                return sendMessage(rsp);
            }
            return false;

        }
        return false;
    }


    boolean on_req_MP3(XcpMessage req)  {

        if ( req.is_QUERY_REQ() ) {
            /*
            1. mp3 파일 조회
            - 조회 요청
            <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=mp3

            - 조회 응답(전체 mp3 리스트 조회 )
            <start=0000&0>$version=2.0$copy=00-0000$cmd=21$dongho=101&201$target=mp3
            #no=1#url=#use=1#filename=aaa.mp3#no=2#url=#use=0#filename=bbb.mp3

            - 에러
            <start=0000&0>$version=2.0$copy=00-
            0000$cmd=11$dongho=101&201$target=mp3#err=0001&저장오류
             */

            XcpMessage rsp = newResponse(req);
            File path = new File(PICTURE_PATH);
            String[] files = path.list(new FilenameFilter(){
                public boolean accept(File dir, String name) {
                    return name.endsWith(".mp3") ;
                }
            });

            if ( files == null || files.length == 0 ) {
                rsp.setBodyValue("err", "0001&이미지가 존재하지 않습니다.");
                sendMessage(rsp);
                return true;
            }

            for(int i = 0 ; i < files.length ; ++i) {
                rsp.setBodyValue("no", i+1);
                rsp.setBodyValue("url", "");
                rsp.setBodyValue("use", 0);
                rsp.setBodyValue("filename", files[i]);
            }
            return sendMessage(rsp);
        }
        else if ( req.is_CTRL_REQ() ) {
            String mode = req.bodyValue("mode");
            if ( mode == "upload") {
            }
            else if ( mode == "delete") {
            }
            else if ( mode == "update") {
// need activity
//                Intent intent = new Intent();
//                startActivityForResult()
            }
            else {
                XcpMessage rsp = newResponse(req);
                rsp.setBodyValue("mode", mode);
                rsp.setBodyValue("err", "0001& 명령어가 처리되지 않았습니다.");
                return sendMessage(rsp);
            }
            return false;

        }
 
        return false;
    }

    public boolean sample_req_Q_SMS_TEL() {
        /*
        1. 핸드폰 리스트 조회
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=sms_tel

        - 조회 응답(전체 SMS 리스트 조회 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&102$target=sms_tel
        #use_all=1
        #no=1#phone=111-111-111#use=1
        #no=2#phone=222-222-222#use=1

        - 에러
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=sms_tel
        #use_all=1#err=2270&NoData
         */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__SMS_TEL);
		return request(req, (reply)-> {
            if ( !reply.isOk() )
		        return;

            XcpMessage rsp = reply.response();
            /*
                #use_all 전체 번호에 대한 수신 여부 판단. 각 개별의 use 값에 대해서 우선함
            */
            String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
//                #err=0001&이지빌 인터넷 미가입자 입니다.
//                #err=0002&데이터가 없습니다.
//                display err
                return;
            }
            String use_all = rsp.bodyValue("use_all");
            String[][] table = rsp.bodyValueTable("no", "phone", "use");
//            for(int i = 0 ; i < table.length ; ++i) {
//                table[i][0];    // no
//                table[i][1];    // phone
//                table[i][2];    // use
//                use_all // "use" 보다 우선한다.
//            }
        });
	}

    public boolean sample_req_C_SMS_TEL(String[] phoneArray) {
        /*
        2. 핸드폰 수신 여부 저장
        - 제어 요청( 설정 값 저장 )
        <start=0000&0>$version=2.0$copy=00-0000$cmd=20$dongho=101&102$target=sms_tel
        #no=1#phone=111-111-111#use=1#no=2#phone=222-222-222#use=1

        - 제어 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=21$dongho=101&201$target=sms_tel

        - 에러 1: 조회 데이터가 없을 때
        <start=0000&0>$version=2.0$copy=00-0000$cmd=21$dongho=101&201$target=sms_tel
        #err=2270&NoData
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__SMS_TEL);
		req.setBodyValue("use_all", "1");
		for( int i=0 ; i < phoneArray.length ; ++i) {
            req.setBodyValue("no", i+1);
            req.setBodyValue("phone", phoneArray[i]);
            req.setBodyValue("use", "1");
        }
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // #err=0001&이지빌 인터넷 미가입자 입니다.
                return;
            }

            // do something
        });
	}

    public boolean sample_req_Q_MANFEE_LIST(int start, int end) {
        /*
        1. 관리비 리스트 조회
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-
        0000$cmd=10$dongho=101&201$target=manfee_list#param=1&5

        - 조회 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=manfee_list
        #no=1#title=4 월관리비#date=20070326121223
        #no=2#title=3 월관리비#date=20070326121223
        #no=3#title=2 월관리비#date=20070326121223

        - 에러
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=manfee_list
        #err=2270&NoData
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__MANFEE_LIST);
		req.setBodyValue("param", Xcp.make_range(start, end) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            String[][] table = rsp.bodyValueTable("no", "title", "date");
            // do something
        });
	}

    public boolean sample_req_Q_MANFEE(int year, int month) {
        /*
        2. 관리비 내역 조회 선택
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=manfee
        #param=2007&03

        - 조회 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=manfee
        #no=1#title=3 월관리비#time=20070326121223#total=20000#general=100#elec=100#water=100
        #heat=100#etc=100

        - 에러
        <start=0000&0>$version=2.0$copy=00-0000$cmd=21$dongho=101&201$target=manfee
        #err=2270&NoData
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__MANFEE);
		req.setBodyValue("param", String.format(Locale.US, "%d&%02d", year, month) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("no");
            rsp.bodyValue("title");
            rsp.bodyValue("total");
            rsp.bodyValue("water");
            // do something
        });
	}

    /**
     *
     * @param type
     *   #type=13 : 공지
     *   #type=14 : 자이안라운지
     *   #type=15 :인터넷문의
     *   #type=16 : 비상콜
     *   #type=17 : 비상 안내
     *   #type=18 : make up room
     *   #type=19 : do not disturb
     *   #type=20 : 개별세대공지
     *   #type=21 : 지역정보안내
     * @param start
     * @param end
     * @return
     */
    public boolean sample_req_Q_OFCAN_LIST(int type, int start, int end) {
        /*
        1. 공지사항 리스트 조회
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=ofcan_list
        #type=20
        #param=1&5

        - 조회 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=ofcan_list
        #type=20#total=3
        #no=1#title=쓰레기 수거 안내#date=20070326121223
        #no=2#title=가을 음악회 안내#date=20070326121223
        #no=3#title=반상회 안내#date=20070326121223

        - 에러
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=ofcan_list
        #type=20#err=0001&공지사항이 존재하지않습니다.

        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=ofcan_list
        #type=20#err=2270&NoData
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__OFCAN_LIST);
		req.setBodyValue("type", "" + type );
		req.setBodyValue("param", Xcp.make_range(start, end) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            String[][] table = rsp.bodyValueTable("no", "title", "date");
            // do something
        });
	}

    public boolean sample_req_Q_OFCAN(String type, String no) {
        /*
        2. 공지사항 내용 조회
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-
        0000$cmd=10$dongho=101&201$target=ofcan#type=20#param=1

        - 조회 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=ofcan
        #type=20#no=100#time=20070326121223#title=쓰레기 수거 안내#content=쓰레기 봉투를
        이용하여 버려주시기 바랍니다

        - 에러
        <start=0000&0>$version=2.0$copy=00-
        0000$cmd=21$dongho=101&201$target=ofcan#err=0001&공지사항이 존재하지 않습니다.
        <start=0000&0>$version=2.0$copy=00-
        0000$cmd=21$dongho=101&201$target=ofcan#err=2270&NoData
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__OFCAN);
		req.setBodyValue("type", type );
		req.setBodyValue("param", no );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("no");
            rsp.bodyValue("time");
            rsp.bodyValue("title");
            rsp.bodyValue("content");
            // do something
        });
	}

    boolean on_req_OFCAN(XcpMessage req)
    {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );

        if ( req.is_EVENT_REQ() ) {
            /*
            3. 공지사항 이벤트 통보
            - 일반 공지 이벤트 통보
            <start=0000&0>$version=2.0$copy=00-0000$cmd=30$dongho=101&201$target=ofcan
            or
            <start=0000&0>$version=2.0$copy=00-0000$cmd=30$dongho=101&201$target=ofcan
            #type=13

            - 이벤트 통보 응답
            <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&201$target=ofcan
            #type=13

            - 에러
            <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&201$target=ofcan
            #type=13#err=0001&error-
             */

            // EHW-1050 : do not append type
            /*
            // Response
            // <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&201$target=ofcan    ???? #type=13
            //
            //QString resp = header.createMessage(Xcp.TARGET__OFCAN, Xcp.CMD__EVENT_RSP,
            //	QString("type=%1").arg(type));
            QString resp = header.createMessage(Xcp.TARGET__OFCAN, Xcp.CMD__EVENT_RSP, "");
            */

            OfcanEvent event = new OfcanEvent(req);
            OfcanMessage.broadcastEvent(OfcanEvent.EVT_OFCAN_EVENT,TAG, event);
            XcpMessage resp = newResponse(req);
            if(resp != null) {
                // must set body "type" as "13"
                resp.setBodyValue("type", "13");
                return sendMessage(resp);
            }
        }
        return false;
    }

    /*
    #no=1 : 전기 검침
    #no=2 : 수도 검침
    #no=3 : 가스 검침
    #no=4 : 온수 검침
    #no=5 : 열럄 검침
    #no=6 : 송전
    #no=7 : 태양열
    */
    boolean on_req_METER(XcpMessage req)
    {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );

        if ( req.is_QUERY_REQ() ) {
            /*
            1. 실시간 검침 조회(단지서버 -> 홈 서버)
            - 조회 요청( 특수 조건:항상 0 으로만 조회합니다.)
            <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&102$target=meter
            #no=0

            - 조회 응답
            <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&102$target=meter
            #no=1#curval=191.1#date=20070315120000
            #no=2#curval=191.1#date=20070315120000
            #no=3#curval=191.1#date=20070315120000
            #no=4#curval=191.1#date=20070315120000
            #no=5#curval=191.1#date=20070315120000

            - 에러
            <start=0000&0>$version=2.0$copy=00-
            0000$cmd=11$dongho=101&201$target=meter#err=0001&error-

            주) 각 계량기의 검침 수량 및 사용량 분석 수치 값은 현장에 연동하는 수량 만큼만 사용한다.
            예)
            3 종( 전기,수도,가스),
            5 종(전기,수도,가스,온수, 열량), = (전기1,수도2,가스3,온수4,열량5)
            단, 2017 년 6 월 강남자곡동 더시그넘 하우스에 한하여 5 종은 전기,수도,냉방,온수, 열량으로 적용한다.
            7 종(전기,수도,가스,온수,열량,송전,태양열),
            8 종(전기,수도,가스,온수,열량,송전,태양열사용량)
             */

            // 1. read spec
            // 2. read meterread
            // 3. make msg
            // 4. send response

//            MeterEvent event = new MeterEvent(req);
//            event.broadcastEvent(MeterEvent.EVT_RSP_METER_CURRENT,TAG, event);
            //TODO: 임동현 : 작동확인 해야함.
            /*int requestedMeter = 0;
            if(!TextUtils.isEmpty(req.bodyValue("no"))){
                requestedMeter = Integer.parseInt(req.bodyValue("no"));
                XcpMessage rsp = newResponse(req);
                if(rsp != null ) {
                    rsp.setBodyValue("no", requestedMeter);

                    ArrayList<String> meterValue = new ArrayList<>();
                    ProxyPojo.XiMeterReadMap xiMeterReadMap = (ProxyPojo.XiMeterReadMap) ProxyServer.getInstance().getDeviceMap(HaGlobal.DEV_ID_xi_meterread);
                    ProxyPojo.MeterReadMap meterReadMap = (ProxyPojo.MeterReadMap)ProxyServer.getInstance().getDeviceMap(HaGlobal.DEV_ID_tta_meterread);
                    if(xiMeterReadMap.size() > 0) {
                        for (int subId : xiMeterReadMap.keySet()) {
                            XiMeterRead meterRead = xiMeterReadMap.get(subId);
                            if (meterRead.m_discovered) {
                                int energy_type = (subId & 0x0f);
                                switch (energy_type) {
                                    case XiMeterRead.ID_ELECTRIC: //전기
                                        meterValue.set(0,String.format("%.2f",meterRead.status.getValue()));
                                        break;
                                    case XiMeterRead.ID_WATER: //수도
                                        meterValue.set(1,String.format("%.2f",meterRead.status.getValue()));
                                        break;
                                    case XiMeterRead.ID_GAS: //가스
                                        meterValue.set(2,String.format("%.2f",meterRead.status.getValue()));
                                        break;
                                    case XiMeterRead.ID_HOTWATER: //온수
                                        meterValue.set(3,String.format("%.2f",meterRead.status.getValue()));
                                        break;
                                    case XiMeterRead.ID_HEAT: //열량
                                        meterValue.set(4,String.format("%.2f",meterRead.status.getValue()));
                                        break;
                                }
                            }
                        }
                    }else if(meterReadMap.size() > 0) {
                        Map.Entry<Integer, TtaXiMeterRead> meterReadEntry = meterReadMap.entrySet().iterator().next();
                        // Only one meter should be present..
                        TtaXiMeterRead meterRead = meterReadEntry.getValue();

                        if(meterRead.m_discovered) {
                            int index = 0;
                            for (TtaXiMeterRead.Status status : meterRead.status) {
                                switch (status.subId) {
                                    case TtaXiMeterRead.ID_ELECTRICITY:
                                        meterValue.set(0,String.format("%.2f",meterRead.status.get(index).getValue()));
                                        break;
                                    case TtaXiMeterRead.ID_WATER:
                                        meterValue.set(1,String.format("%.2f",meterRead.status.get(index).getValue()));
                                        break;
                                    case TtaXiMeterRead.ID_GAS:
                                        meterValue.set(2,String.format("%.2f",meterRead.status.get(index).getValue()));
                                        break;
                                    case TtaXiMeterRead.ID_HOTWATER:
                                        meterValue.set(3,String.format("%.2f",meterRead.status.get(index).getValue()));
                                        break;
                                    case TtaXiMeterRead.ID_HEAT:
                                        meterValue.set(4,String.format("%.2f",meterRead.status.get(index).getValue()));
                                        break;
                                }
                            }
                        }
                    }
                    if(meterValue.size()<requestedMeter || TextUtils.isEmpty(meterValue.get(requestedMeter-1))){
                        return false;
                    }
                    rsp.setBodyValue("curval", meterValue.get(requestedMeter-1));
                    rsp.setBodyValue("date", PtDateTime.current().toString("yyyyMMddHHmmss"));

                    return sendMessage(rsp);
                }
            }else{
                XcpMessage rsp = newResponse(req);
                if(rsp != null){
                    String err = rsp.bodyValue("err");
                    if ( !err.isEmpty() )
                        return false; // error
                }
            }*/
        }
        return false;
    }

    public boolean sample_req_Q_METER() {
        /*
        2. 누적 검침 조회(홈 서버->단지서버)
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&102$target=meter
        #no=0

        - 조회 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&102$target=meter
        #no=1#curval=191.1#date=20070315120000
        #no=2#curval=191.1#date=20070315120000
        #no=3#curval=191.1#date=20070315120000
        #no=4#curval=191.1#date=20070315120000
        #no=5#curval=191.1#date=20070315120000

        - 에러
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=meter
        #err=0001&error-
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__METER);
		req.setBodyValue("no", "0" );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            String[][] table = rsp.bodyValueTable("no", "curval", "date");
            // do something
        });
	}


    boolean on_req_METER_INIT(XcpMessage req)
    {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );

        if ( req.is_CTRL_REQ() ) {
            XcpMessage rsp = newResponse(req);
            rsp.setBodyValue("err", Xcp.ERR__NOT_SUPPORTED);
            sendMessage(rsp);
        }
        return false;
    }

    boolean on_req_METER_CPS(XcpMessage req)
    {
        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );

        if ( req.is_CTRL_REQ()) {
            XcpMessage rsp = newResponse(req);
            rsp.setBodyValue("err", Xcp.ERR__NOT_SUPPORTED);
            sendMessage(rsp);
        }
        return false;
    }

    /*
    ----------------------
    TARGET=METER
    ----------------------
    1. 실시간 검칭 조회 ( S->C )
    [S->C] cmd=10, target=meter
    [C->S] cmd=11, target=meter, from 485

    2. 누적 검침 조회 ( C->S )
    [C->S] cmd=10, target=meter
    [S->C] cmd=11, target=meter, accm

    3. 원격검침 초기화 ( S->C )
    unsupported

    4. 원격검침 보전 계수 초기화 ( S->C )
    unsupported

    ----------------------
    TARGET=METERMONTH
    ----------------------
    // REQUEST 각자 알아서 처리할 것.
    5. 원격검침 월간 수치 조회
    1) mode=list 또는 “값이 없을 때” 또는 “mode 파라 미터가 없을 때” (단순 월별 데이터 조회 )
    2) mode=month ( 월별 수치 조회 )
    3) mode=day ( 일별 조회 )

    6. 에너지 사용량 조회
    1) mode=month_ems ( Deprecated )
    2) mode=month_ems ( 목표값 설정  )
    3) mode=ems_target ( 목표값 설정  )

    7. 에너지 사용량 조회 ( 에너지 서버 연동 )
    1) mode=month_energy ( 평균값 및 목표 값 조회 )
    2) mode=month_accumulate ( 누적값 조회   )

    8. 에너지 사용량 조회 ( 월패드 메인 )
    1) mode=ems_main ( 특정 현장에서만 사용되는 모드임 )

    9. 목표값 초과 이벤트
    1) mode=ems_event ( 목표값 초과시 이벤트 ) S->C
    2) mode=ems_event2 ( 목표값 초과 및 사용량 정보 이벤트 ) S->C

    */
    public boolean sample_req_Q_METERMONTH_list(int yyyy, int mm) {
        /*
        5. 원격검침 월간 수치 조회
        1) mode=list 또는 “값이 없을 때” 또는 “mode 파라 미터가 없을 때” (단순 월별데이터 조회 )
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&102$target=metermonth
        #param=2007&03#mode=list

        - 조회 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&102$target=metermonth
        #param=200703
        #no=1#curval=191.5
        #no=2#curval=191.5
        #no=3#curval=191.1
        #no=4#curval=191.1
        #no=5#curval=191.1
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__METERMONTH);
		req.setBodyValue("mode", "list" );
		req.setBodyValue("param", Xcp.make_date(yyyy, mm) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            String[][] table = rsp.bodyValueTable("no", "curval", "date");
            // do something
        });
	}

    public boolean sample_req_Q_METERMONTH_month(int yyyy, int mm) {
        /*
        2) mode=month ( 월별 수치 조회 )
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&102$target=metermonth
        #param=2007&03#mode=month

        - 조회 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&102$target=metermonth
        #mode=month#param=2007&03
        #curmonth=200703#curvals=2323&3434&4345&9879&98
        #prevmonth=2007&02#prevvals=232.1&343.2&434.1&987.1&97#totalvals=232.3&343.4&434.5&987.9&98
        #flag=1&2&1&2&1

        “전기&수도&가스&온수&열량&송전&태양열” 순으로 만든다
        주) 각 계량기의 검침 수량 및 사용량 분석 수치 값은 현장에 연동하는 수량 만큼만 사용한다.
        예)
        3 종( 전기,수도,가스),
        5 종(전기,수도,가스,온수, 열량),
        단, 2017 년 6 월 강남자곡동 더시그넘 하우스에 한하여 5 종은 전기,수도,냉방,온수, 열량으로 적용한다.
        7 종(전기,수도,가스,온수,열량,송전,태양열),
        8 종(전기,수도,가스,온수,열량,송전,태양열사용량)
        */

		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__METERMONTH);
		req.setBodyValue("mode", "month" );
		req.setBodyValue("param", Xcp.make_date(yyyy, mm) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }
            // do something
        });
	}

    public boolean sample_req_Q_METERMONTH_day(int yyyy, int mm, int dd) {
        /*
        3) mode=day ( 일별 조회 )
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&102$target=metermonth
        #mode=day
        #param=2007&03&21

        - 조회 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&102$target=metermonth
        #mode=day
        #param=2007&03&21
        #todayvals=232.3&343.4&434.5&987.9&9.8
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__METERMONTH);
		req.setBodyValue("mode", "day" );
		req.setBodyValue("param", Xcp.make_date(yyyy, mm, dd) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }
            // do something
        });
	}

    boolean on_req_METERMONTH(XcpMessage req)  {

        if ( mDebugMsg ) PtLog.i(TAG, "on_req_XXX(): %s", req.toSummary() );

        if ( req.is_EVENT_REQ() ) {

            String mode = req.bodyValue("mode");
            if ( mode.equals("ems_event")) {

                /*
                1) mode= ems_event ( 목표값 초과시 이벤트 )
                - 이벤트 통보( 단지 서버 -> 홈 서버 )
                <start=0000&0>$version=2.0$copy=00-0000$cmd=30$dongho=101&102$target=metermonth
                #mode=ems_event
                #targetvals_flag=1&0&0&0&0

                - 이벤트 응답(홈 서버 -> 단지서버)
                <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&102$target=metermonth
                #mode=ems_event
                #res=ok

                - 이벤트 응답 에러 (홈 서버 -> 단지서버 )
                <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&102$target=metermonth
                #mode=ems_event#res=fail
                 */

                EnergyMessage.broadcastEvent(mode, mode, req);

                XcpMessage rsp = newResponse(req);
                rsp.setBodyValue("mode", "ems_event"); // CJH 2023-02-03 : 신동탄포레자이 현장 이슈 개선
                rsp.setBodyValue("res", "ok");
                return sendMessage(rsp);
            }
            else if ( mode.equals("ems_event2")) {
                /*
                2) mode= ems_event2 ( 목표값 초과 및 사용량 정보 이벤트 )
                - 이벤트 통보( 단지 서버 -> 홈 서버 )
                <start=0000&0>$version=2.0$copy=00-000$cmd=30$dongho=101&102$target=metermonth
                #mode=ems_event2
                #targetvals_flag=1&0&0&0&0
                #curmonth=2015&10
                #curvals=000.0&000.0&000.0&000.0&000.0
                #cur_sametype_avr=000.0&000.0&000.0&000.0&000.0
                #prevmonth=2015&09
                #prevvals=000.0&000.0&000.0&000.0&000.0
                #prev_sametype_avr=000.0&000.0&000.0&000.0&000.0

                - 이벤트 응답(홈 서버 -> 단지서버)
                <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&102$target=metermonth
                #mode=ems_event2
                #res=ok

                - 이벤트 응답 에러 (홈 서버 -> 단지서버 )
                <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&102$target=metermonth
                #mode=ems_event2
                #res=fail
                 */

                EnergyMessage.broadcastEvent(mode, mode, req);

                XcpMessage rsp = newResponse(req);
                rsp.setBodyValue("mode", "ems_event2"); // CJH 2023-02-03 : 신동탄포레자이 현장 이슈 개선
                rsp.setBodyValue("res", "ok");
                return sendMessage(rsp);
            }
        }
//        else if(req.is_QUERY_RSP()) {
//            String mode = req.bodyValue("mode");
//            switch(mode) {
//                case "month":
//                    break;
//                case "month_co2":
//                    break;
//                case "month_ems":
//                    break;
//                case "day": // this month usage
//                    break;
//                case "day_co2":
//                    break;
//                case "list":
//                    break;
//                case "list_co2":
//                    break;
//                case "ems_main":
//                    break;
//                case "month_ems2":
//                    break;
//                case "month_energy": // previous monthly usage
//                    break;
//                case "month_accmulate": // typo ??
//                case "month_accumulate":
//                    break;
//            }
//        }
        return false;
    }

    /**
     *
     * @param no  1 base. ( 1부터 시작한다.)  1번이 어떤 CCTV 인지는, spec 으로부터 가져온다.
     * @see  HaSpec.CctvItemMap , HaSpec.CctvItem
     */
    //TODO: 이용을 하는 것인지 판단이 필요하다. 아울러 Spec 파일과 비교를 해야 하는 것인가?
    public boolean sample_req_Q_CCTV(int no) {
        /*
            1. CCTV 정보 조회
            - 조회 요청
            <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=cctv#no=1

            - 조회 응답
            <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=cctv
            #no=1
            #ip=10.10.10.90
            #port=27000
            #user=AAA
            #password=1234
            #cameraid=1

            - 에러
            <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=cctv
            #err=2270&NoData
        */
        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__CCTV);
        req.setBodyValue("no", no);
        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error

            // do something
            rsp.bodyValue("ip");
            rsp.bodyValue("port");
            rsp.bodyValue("user");
            rsp.bodyValue("password");
            rsp.bodyValue("cameraid");
        });
    }

    public boolean sample_req_Q_PARKING_list(int start, int end) {
        /*
        2. 주차관제 리스트 조회
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=parking
        #mode=0#param=1&5

        - 조회 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=parking
        #mode=0#total=3
        #no=1#inout=1#carno=서울가 1234#time=20070503121212
        #no=2#inout=1#carno=서울가 1235#time=20070504121212
        #no=3#inout=1#carno=서울가 1236#time=20070505121212

        -에러
        <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=parking
        #mode=0#total=0#err=2270&NoData
        */
        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__PARKING);
        req.setBodyValue("mode", "0");
        req.setBodyValue("param", Xcp.make_range(start, end));
        req.setBodyValue("dongho", Xcp.make_range(mDong, mHo) );

        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error

            // do something
            rsp.bodyValue("total");
            rsp.bodyValueTable("no", "inout", "carno", "time");
        });
    }

    public boolean sample_req_Q_PARKING_reserve(int start, int end) {
        /*
        3. 주차 예약 리스트 조회
        - 조회 요청
        <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=parking
        #mode=1#dongho=101&201#param=1&10

        - 조회 응답
        * 예약 차량 번호에 개수 만큼 #no=1#carno=1111 ~ #no=n#carno=???? 를   반복한다.
        * 각 차량별로 입차 예약 시간을 설정할 수 있다.
        <start=0000&0>$version=2.0$copy=00-0000$dongho=100&201$cmd=11$target=parking
        #mode=1#dongho=101&201
        #no=1#inout=0#time=20070101120000#carno=1111
        #no=2#inout=0#time=20070101120000#carno=2222
        #no=3#inout=0#time=20070101120000#carno=3333
        #no=4#inout=0#time=20070101120000#carno=4444
        */
        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__PARKING);
        req.setBodyValue("mode", "1");
        req.setBodyValue("param", Xcp.make_range(start, end));
        req.setBodyValue("dongho", Xcp.make_range(mDong, mHo) );
        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error

            // do something
            rsp.bodyValue("total");
            rsp.bodyValueTable("no", "inout", "time", "carno");
        });
    }

    /*
    각자 알아서 구현 할 것.
    4. 주차 예약 리스트 저장 ( CTRL_REQ )
    5. 주차 예약 리스트 삭제 ( CTRL_REQ )
    6. 차량 번호를 이용한 주차위치 조회 ( CTRL_REQ )
    7. 차량 이력 삭제 ( CTRL_REQ )
     */


    boolean on_req_PARKING(XcpMessage req)  {

        if ( req.is_QUERY_RSP() || req.is_CTRL_RSP()) {
            // 입차 예약 조회 응답, 입차 예약 응답
            return ParkingMessage.onReceived(req);
        }


        if ( req.is_EVENT_REQ()) {
            Log.e("PARKING_EVENT", "PARKING");
            return ParkingMessage.onReceived(req);

        /*
        1. 주차관제 이벤트 전송
        - 이벤트 통보
        <start=0000&0>$version=2.0$copy=00-0000$cmd=30$dongho=101&102$target=parking
        #mode=0
        #param=
        #dongho=101&102
        #inout=0
        #carno=47 더 1234
        #time=20070315121212

        - 이벤트 통보 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&102$target=parking#mode=0
        */

//            ParkingEvent event = new ParkingEvent(req);
//            ParkingMessage.broadcastEvent(ParkingEvent.EVT_PARKING_EVENT, TAG, true, event);
//            Log.e("PARKING_EVENT", "PARKING");
//            ToastEx.makeText(getContext(), R.string.s08_car_in, Toast.LENGTH_SHORT).show();
//            return sendMessage( newResponse(req) );

        }
        return false;
    }


//    public boolean sample_req_E_ELEVATOR_open(int start, int end) {
//        /*
//        1. 엘리베이터 이동 정보 요청
//        - 요청
//        <start=0000&0>$version=2.0$copy=00-0000$cmd=30$dongho=101&102$target=elevator
//        #mode=open#dongho=101&102
//
//        - 응답
//        <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=100&700$target=elevator
//        #mode=open#dongho=101&102#no=1#direction=up#flow=3#no=2#direction=up#flow=3
//        #no=3#direction=up#flow=3
//
//        - 에러
//        <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=100&700$target=elevator
//        #mode=open#dongho=101&102#err=0001&error
//        */
//        XcpMessage req = newRequest(Xcp.CMD__EVENT_REQ, Xcp.TARGET__ELEVATOR);
//        req.setBodyValue("mode", "open");
//        req.setBodyValue("dongho", makeDongHo() );
//        return request(req, (reply)-> {
//            if ( !reply.isOk() )
//                return;
//
//            XcpMessage rsp = reply.response();
//            String err = rsp.bodyValue("err");
//            if ( !err.isEmpty() )
//                return; // error
//
//            // do something
//        });
//    }
//
//    public boolean sample_req_E_ELEVATOR_close() {
//        /*
//        2. 엘리베이터 이동 정보 중지 요청[ 홈 서버가 중지 요청 하는 경우 ]
//        - 요청
//        <start=0000&0>$version=2.0$copy=00-0000$cmd=30$dongho=101&201$target=elevator
//        #mode=close#dongho=101&201
//
//        - 응답
//        <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&102$target=elevator
//        #mode=close#dongho=101&201
//
//        - 에러
//        <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&102$target=elevator
//        #mode=close#dongho=101&201
//        #err=0001&error
//        */
//        XcpMessage req = newRequest(Xcp.CMD__EVENT_REQ, Xcp.TARGET__ELEVATOR);
//        req.setBodyValue("mode", "close");
//        req.setBodyValue("dongho", makeDongHo() );
//        return request(req, (reply)-> {
//            if ( !reply.isOk() )
//                return;
//
//            XcpMessage rsp = reply.response();
//            String err = rsp.bodyValue("err");
//            if ( !err.isEmpty() )
//                return; // error
//
//            // do something
//        });
//    }
    boolean on_req_ELEVATOR(XcpMessage msg) {
        return ElevatorMessage.getInstance().onReceived(msg);
    }


    public boolean sample_req_E_ROCKER(String mode, String rockername, String boxno, String checktime) {
        /*
        2. 월패드 택배 공지 확인 통보 (월패드->단지서버)
        - 통보
        <start=0000&0>$version=2.0$cmd=30$dongho=100&201$target=rocker#dongho=101&201#n
        o=1#mode=도착#rockername=105 동#boxno=5#checktime=20080313132451

        - 응답
        <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&201$target=rocker

        - 에러
        <start=0000&0>$version=2.0$copy=00-0000$cmd=31$dongho=101&201$target=rocker
        #err=0001&errormessage
        */
        XcpMessage req = newRequest(Xcp.CMD__EVENT_REQ, Xcp.TARGET__ROCKER);
        req.setBodyValue("dongho", makeDongHo());
        req.setBodyValue("mode", mode);
        req.setBodyValue("rockername", rockername);
        req.setBodyValue("boxno", boxno);
        req.setBodyValue("checktime", checktime);
        return request(req, (reply) -> {
            if (!reply.isOk())
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if (!err.isEmpty())
                return; // error

        });
    }

    public boolean sample_req_Q_ROCKER(int start, int end) {
        /*
        3. 택배 리스트 조회
        - 요청
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=rocker
        #param=1&5

        - 응답
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=rocker
        #total=5
        #no=1#danji=0000#mode=도착#dongho=101&201#rockername=105 동#boxno=5#intime=200
        80313132451#contents=한진택배#paytype=02#amount=5000#deliverymanphone=000000000
        #sendphone=01011112222#receivphone=11111111111#msg=aaaaaaaaaaa
        #contents=한진택배#paytype=02#amount=5000#sendphone=01011112222

        #no=2#danji=0000#mode=도착#dongho=101&201#rockername=105 동#boxno=5#intime=200
        80312132451#contents=한진택배#paytype=02#amount=5000#deliverymanphone=000000000
        #sendphone=01011112222#receivphone=11111111111#msg=aaaaaaaaaaa
        #contents=한진택배#paytype=02#amount=5000#sendphone=01011112222
        ...

        -에러
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=rocker
        #total=5#err=2270&NoData
        */
        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__ROCKER);
        req.setBodyValue("param", Xcp.make_range(start, end) );
        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error

            // do something
            rsp.bodyValueTable("no"
                    , "dannji"
                    , "mode"
                    , "dongho"
                    , "rockername"
                    , "boxno"
                    , "intime"
                    , "contents"
                    , "paytype"
                    , "amount"
                    , "deliverymanphone"
                    , "sendphone"
                    , "receivphone"
                    , "msg"
                    , "contents"
                    , "paytype"
                    , "amount"
                    , "sendphone");
        });
    }


    public boolean sample_req_C_ROCKER(String intime) {
        /*
        4. 택배 삭제
        - 요청
        <start=0000&0>$version=2.0$cmd=20$dongho=101&201$target=rocker
        #mode=rm
        #intime=20080310132451

        - 응답( 삭제 성공)
        <start=0000&0>$version=2.0$cmd=21$dongho=101&201$target=rocker
        #mode=rm
        #intime=20080310132451
        #res=ok

        - 응답( 삭제 실패)
        <start=0000&0>$version=2.0$cmd=21$dongho=101&201$target=rocker
        #mode=rm
        #intime=20080310132451
        #res=faile
        */
        XcpMessage req = newRequest(Xcp.CMD__CTRL_REQ, Xcp.TARGET__ROCKER);
        req.setBodyValue("mode", "rm" );
        req.setBodyValue("intime", intime );
        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error

        });
    }


    boolean on_req_ROCKER(XcpMessage req)  {
         if ( req.is_EVENT_REQ() ) {
            return DeliveryMessage.onReceived(req);
        }
        return false;
    }

    public boolean sample_req_Q_EMERGENCY(int start, int end) {
        /*
        2. 비상콜 발생 이력 조회
        - 요청( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=emergency#param=1&5

        - 응답( 단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$cmd=11$dongho=100&112$target=emergency
        $total=5
        #no=1#location=103 동주차장 D 구역#locationcode=0010,0004#locatinfloor=b1
        #no=2#location=103 동주차장 D 구역#locationcode=0005,0002#locatinfloor=b1

        -에러
        <start=0000&0>$version=2.0$cmd=11$dongho=100&112$target=emergency
        $total=5#err=2270&NoData
        */

        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__EMERGENCY);
        req.setBodyValue("param", Xcp.make_range(start, end) );
        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error

            rsp.bodyValueTable("no", "location", "locationcode", "locationfloor");
        });
    }

    boolean on_req_EMERGENCY(XcpMessage req)   {

        if ( req.is_EVENT_REQ() ) {
            /*
            1. 비상콜 발생 위치 통보
            - 통보( 단지서버 -> 홈 서버 )
            <start=0000&0>$version=2.0$copy=00-0000-0000$cmd=30$dongho=101&201$target=emergency
            #no=1#tagid=99#camera=1,2,3#location=103 동주차장 D 구역#dongho=101&201#locationcode=0010,0004#locationfloor=b1

            - 응답( 홈 서버 -> 단지서버 )
            <start=0000&0>$version=2.0$cmd=31$dongho=101&201$copy=[단지서버가전송하는스트링]$target=emergency

            - 에러( 홈 서버 -> 단지서버 )
            <start=0000&0>$version=2.0$cmd=31$dongho=101&201$copy=[단지서버가
            전송하는스트링]$target=emergency#err=0001&error-
            */
            doNotify(req);

            if ( req.is_EVENT_REQ() ) {
                return EmergencyMessage.onReceived(req);
            }
            return sendMessage(newResponse(req));
        }
        return false;
    }

    public boolean sample_req_Q_LOCATIONINFO() {
        /*
        3. 주차위치 조회(최종 저장 위치 )
        - 통보( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=locationinformation

        - 응답( 단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=
        locationinformation#no=1#location=103 동주차장 D 구역#locationcode=0002,0050#locatinfloor=b1#no=2
        #location=104 동주차장 D 구역#locationcode=0005,0010#locatinfloor=b1
        */

        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__LOCATIONINFO);
        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error

            rsp.bodyValueTable("no", "location", "locationcode", "locationfloor");
        });
    }

    public boolean sample_req_Q_LOCATIONINFO(String carno) {
        /*
       4. 주차위치 조회 2 (최종 저장 위치)
        차량번호로 위치를 조회할 수 있다.
        - 통보( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=locationinformation
        #dongho=102&201
        #carno=13 가 1234

        - 응답( 단지서버 -> 홈 서버 )
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=locationinformation
        #dongho=101&201
        #carno=13 가 1234

        - 에러(단지서버-> 홈서버)
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=locationinformation
        #dongho=101&201
        #carno=13 가 1245
        #err=2270&NoData
        */

        XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__LOCATIONINFO);
        req.setBodyValue("dongho", makeDongHo() );
        req.setBodyValue("carno", carno );
        return request(req, (reply)-> {
            if ( !reply.isOk() )
                return;

            XcpMessage rsp = reply.response();
            String err = rsp.bodyValue("err");
            if ( !err.isEmpty() )
                return; // error
        });
    }

    boolean on_req_LOCATIONINFO(XcpMessage req)
    {
        if ( req.is_EVENT_REQ() ) {
            /*
            2. 주차위치 통보
            - 통보( 단지서버 -> 홈 서버 )
            <start=0000&0>$version=2.0$cmd=30$dongho=100&112$copy=00-0000-
            0000$target=locationinformation
            #no=1#tagid=99#camera=1,2,3#location=103 동주차장 D 구역#dongho=101&201#locationcode=0010,000
            4#locatinfloor=b1#map_url=http://10.10.100.90/map/b2.jpg

            - 응답( 홈 서버 -> 단지서버 )
            <start=0000&0>$version=2.0$cmd=31$copy=00-0000-
            0000$dongho=101&201$target=locationinformation
             */
            doNotify(req);
            return ParkingMessage.onReceived(req);
         }
         return false;
    }

    public boolean sample_req_Q_AS(int start, int end) {
        /*
        1. 하자 신청 목록 조회
        - 요청 [월패드 -> 단지서버]
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=as
        #mode=list
        #dongho=101&201
        #param=1&5

        - 응답 [단지서버 -> 월패드]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=as
        #mode=list
        #total=10
        #no=1#id=1#title=월패드 AS 신청
        #no=2#id=21#title=월패드터치불량 AS 신청
        #no=3#id=22#title=원격검침오류신청
        #no=4#id=33#title=도어락 AS 신청
        #no=5#id=34#title=현관문 AS 신청

        - 오류
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=as#mode=list#err=1001&하자신청내역
        이 없습니다.
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__AS);
		req.setBodyValue("mode", "list" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("param", Xcp.make_range(start, end) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("total");
            // do something
        });
	}

    /**
     * "history" one
     * @return
     */
    public boolean sample_req_Q_AS(String id) {
        /*
        3. 하자 이력 조회
        - 요청 [홈서버 -> 단지서버]
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=as
        #mode=history
        #dongho=101&201
        #id=33

        - 응답 [단지서버 -> 홈서버]
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=as
        #mode=history
        #dongho=101&201
        #id=33
        #title=도어락 AS 신청
        #content=2012 년 6 월 10 일 12 시 접수처리됨

        - 오류
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=as
        #mode=history
        #err=1001&조회목록이없습니다
         */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__AS);
		req.setBodyValue("mode", "history" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("id", id );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("title");
            rsp.bodyValue("content");
            // do something
        });
	}

	/*
	 하자내용은 입력하지 않는가?
	 */
    public boolean sample_req_C_AS(String id) {
        /*
        2. 하자 신청
        - 요청 [월패드 -> 단지서버]
        <start=0000&0>$version=2.0$cmd=20$dongho=101&201$target=as
        #mode=call
        #dongho=101&201
        #id=21

        - 응답 [단지서버 -> 홈서버]
        <start=0000&0>$version=2.0$cmd=21$dongho=101&201$target=as
        #mode=call#dongho=101&201#id=21#res=ok

        - 오류
        <start=0000&0>$version=2.0$cmd=21$dongho=101&201$target=as
        #mode=call#dongho=101&201#id=21#res=fail&err=1001&접수가 처리되지 않았습니다.
         */
		XcpMessage req = newRequest(Xcp.CMD__CTRL_REQ, Xcp.TARGET__AS);
		req.setBodyValue("mode", "call" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("id", id );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            // do something
        });
	}


    public boolean sample_req_Q_FAMILY_GUARD_guard_list(int start, int end) {
        /*
        1. 가족안심통보이력
        - 조회( 월패드 -> 단지서버(가족 혹은 자녀안심 서버) )
        <start=0000&0>$version=2.0$copy=00-0000-
        0000$cmd=10$dongho=101&201$target=family_guard#mode=guard_list#dongho=101&201#param=1&5

        - 응답( 단지서버(가족 혹은 자녀안심서버) -> 월패드 )
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$copy=[단지서버가
        전송하는스트링]$target=family_guard#mode=guard_list#dongho=101&201
        #total=158
        #no=1#tagid=11#time=20120925123011#cctv=10.10.10.15,25006,998#location=103 동 XX 구역에서
        비상호출,B1,0007,0010#inout=out
        #no=2#tagid=11#time=20120925113011#cctv=10.10.10.15,25006,998#location=103 동 XX 구역에서
        비상호출,B1,0007,0010#inout=out
        #no=3#tagid=11#time=20120925103011#cctv=10.10.10.15,25006,998#location=103 동 XX 구역에서
        비상호출,B1,0007,0010#inout=out
        #no=4#tagid=11#time=20120925093011#cctv=10.10.10.15,2500,9986#location=103 동 XX 구역에서
        비상호출,B1,0007,0010#inout=out
        #no=5#tagid=11#time=20120925083011#cctv=10.10.10.15,25006,998#location=103 동 XX 구역에서
        비상호출,B1,0007,0010#inout=out

        - 에러( 단지서버(가족 혹은 자녀안심서버) -> 월패드 )
        <start=0000&0>$version=2.0$cmd=31$dongho=101&201$copy=[단지서버가 전송하는스트링]$target=
        family_guard#mode=guard_list#dongho=101&201#err=0001&nodata
         */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__FAMILY_GUARD);
		req.setBodyValue("mode", "guard_list" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("param",  Xcp.make_range(start, end) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            // do something
            XcpMessage rsp  = reply.response();
            rsp.bodyValue("totoal");
            rsp.bodyValueTable("no", "tagid", "time", "cctv", "location", "inout");
        });
	}

    public boolean sample_req_Q_FAMILY_GUARD_tag_list(int start, int end) {
        /*
        2. 세대별 태그 정보 조회
        - 조회( 월패드 -> 단지서버(가족 혹은 자녀안심서버) )
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=family_guard#mode=tag_list
        #dongho=101&201
        #param=1&5

        - 응답( 단지서버(가족 혹은 자녀안심서버) -> 월패드 )
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$copy=00-0000$target=family_guard
        #mode=tag_list#dongho=101&201
        #total=3
        #no=1#tagid=11
        #no=2#tagid=11
        #no=3#tagid=11
         */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__FAMILY_GUARD);
		req.setBodyValue("mode", "tag_list" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("param",  Xcp.make_range(start, end) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            // do something
            XcpMessage rsp  = reply.response();
            rsp.bodyValue("totoal");
            rsp.bodyValueTable("no", "tagid");
        });
	}

    public boolean sample_req_Q_FAMILY_GUARD_taginfo(String tagid) {
        /*
        2. 태그 정보 조회 (해당 태그의 마지막 이벤트 정보)
        - 조회( 월패드 -> 단지서버(가족 혹은 자녀안심서버) )
        <start=0000&0>$version=2.0$cmd=10$dongho=100&201$copy=00-0000$target=family_guard
        #mode=taginfo
        #dongho=101&201
        #tagid=1114

        - 응답( 단지 서버(가족 혹은 자녀안심 서버) -> 월패드 )
        <start=0000&0>$version=2.0$cmd=11$copy=00-0000$dongho=101&201$target=family_guard
        #mode=taginfo
        #dongho=101&201
        #tagid=11
        #cctv=10.10.10.15,25006,998
        #location=103 동 XX 구역에서 비상호출,B1,0007,0010
        #inout=out
         */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__FAMILY_GUARD);
		req.setBodyValue("mode", "taginfo" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("tagid",  tagid );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            // do something
            XcpMessage rsp  = reply.response();
            rsp.bodyValue("tagid");
            rsp.bodyValue("cctv");
            rsp.bodyValue("location");
            rsp.bodyValue("inout");
            //...
        });
	}


    public boolean sample_req_C_FAMILY_GUARD_taginfo(String tagid, String owner) {
        /*
       - 저장( 월패드 -> 단지 서버)
        > 비상콜서버에 전달하지 않음. 외부 연동 필요시 사용 예정
        <start=0000&0>$version=2.0$cmd=20$dongho=100&201$copy=00-0000-0000$target=family_guard
        #mode=taginfo
        #dongho=101&201
        #tagid=1114
        #tag_owner=자녀 1

        - 응답( 단지서버 -> 월패드 )
        <start=0000&0>$version=2.0$cmd=21$copy=00-0000-0000$dongho=101&201$target=family_guard
        #mode=taginfo
        #dongho=101&201
        #tagid=1114
        #tag_owner=자녀 1
         */
		XcpMessage req = newRequest(Xcp.CMD__CTRL_REQ, Xcp.TARGET__FAMILY_GUARD);
		req.setBodyValue("mode", "taginfo" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("tagid",  tagid );
		req.setBodyValue("tagowner",  owner);
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }
        });
	}

    boolean on_req_FAMILY_GUARD(XcpMessage req)  {

        if ( req.is_EVENT_REQ() ) {

            /*
            3. 가족안심 메시지 팝업
            - 이벤트( 단지서버(가족 혹은 자녀안심서버) -> 월패드)
            <start=0000&0>$version=2.0$cmd=30$dongho=101&201$target=family_guard#mode=guard_event
            #dongho=101&201
            #tagid=11
            #time=20120925093011
            #cctv=10.10.10.15,2500,9986
            #location=103 동 XX 구역 에서 비상호출,B1,0007,0010#inout=out

            - 응답( 월패드 -> 단지서버(가족 혹은 자녀안심서버) )
            <start=0000&0>$version=2.0$cmd=31$dongho=101&201$target=family_guard
            #mode=guard_event
            #dongho=101&201#tagid=11
             */

            if ( req.bodyValue("mode").equals("guard_event") ) {
                doNotify(req);
                return sendMessage(newResponse(req));
            }
        }
        return false;
    }

    public boolean sample_req_Q_SURVEY(int start, int end) {
        /*
        1. 목록 조회
        - 조회( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$copy=00-0000-0000$cmd=10$dongho=101&201$target=survery
        #mode=list#param=1&5

        - 응답( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$copy=00-0001$target=survey#mode=list
        #total=2
        #no=1#id=11#period=20130725120000&20130725120000#title=화장실 보수 공사 설문조사#example_cnt=#content=1 보수한다. 2. 보수하지 않는다.
        #no=2#id=21#period=20130725120000&20130725120000#title=쓰레기장 보수 공사설문조사#example_cnt=2#content=2&1 보수한다. 2. 보수하지 않는다.

        - 에러( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$copy=00-0001$target=survey#mode=list
        #err=0001&NoData
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__SURVEY);
		req.setBodyValue("mode", "list" );
		req.setBodyValue("param", Xcp.make_range(start, end) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("total");
            rsp.bodyValue("no");
            rsp.bodyValue("id");
            rsp.bodyValue("time");
            // do something
        });
	}

    public boolean sample_req_C_SURVEY(String id, String choice) {
        /*
        2. 설문투표하기
        - 요청( 홈 서버 -> 단지서버 )
        <start=0000&0>$version=2.0$cmd=20$dongho=101&201$target=survey
        #mode=survey#id=11&survey=1

        - 응답( 단지서버 -> 홈 서버 )
        성공시 -
        <start=0000&0>$version=2.0$cmd=21$dongho=101&201$copy=00-0001$target=survey
        #mode=survey#id=11#survey=11#res=ok

        실패시 -1
        <start=0000&0>$version=2.0$cmd=21$dongho=101&201$copy=00-0001$target=survey
        #mode=survey#id=11#survey=11#res=fail#err=0001&failed

        실패시 -2
        <start=0000&0>$version=2.0$cmd=21$dongho=101&201$copy=00-0001$target=survey
        #mode=survey#id=11#survey=11#res=fail#err=0002&duplicated
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__SURVEY);
		req.setBodyValue("mode", "survey" );
		req.setBodyValue("id", id );
		req.setBodyValue("survey", choice );

		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                // #res=fail#err=0001&failed
                // #res=fail#err=0002&duplicated
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("res");
            // do something
        });
	}

    boolean processAlarm(XcpMessage msg)
    {
//        MessageHeader header;
//        header.parseHeader(message);
//
//        KLOG(mDebugMsg, "[ALARM] Dong = %s, Ho = %s (type=%d)"
//            , qPrintable(header.mDong), qPrintable(header.mHo), header.mCmdType);
//
//        if(header.mCmdType == Xcp.CMD__EVENT_REQ) {
//
//            QString mMode= MsgUtil::parseBody(message, "#mode=");
//            QStringList mNo= MsgUtil::parseBodyList(message, "#no=");
//            QStringList mOnOff= MsgUtil::parseBodyList(message, "#onoff=");
//            QStringList mAlarm= MsgUtil::parseBodyList(message, "#alarm=");
//            QStringList mZone= MsgUtil::parseBodyList(message, "#zone=");
//            QString mDongho = MsgUtil::parseBody(message, "#dongho=");
//            QString mAlarmkey =  MsgUtil::parseBody(message, "#alarmkey=");
//            QString mSection = MsgUtil::parseBody(message, "#section=");
//            QString mShareDongHo = MsgUtil::parseBody(message, "#share_dongho=");
//            // 경비실일 경우....
//            QSrvMsgSecSensor sensor;
//            sensor.m_Address = QString("%1&%2").arg(header.mDong).arg(header.mHo);
//            sensor.m_Command = QString::number((int)header.mCmdType);
//            sensor.m_Copy = header.mCopy;
//            sensor.m_Version = header.mVersion;
//
//            sensor.m_Mode = mMode;
//            foreach(QString no, mNo) {
//                sensor.m_Devices.append(no.toInt());
//            }
//            foreach(QString onoff, mOnOff) {
//                sensor.m_Status.append(onoff.toInt() > 0 ? true:false);
//            }
//            foreach(QString alarm, mAlarm) {
//                sensor.m_Alarms.append(alarm.toInt());
//            }
//            foreach(QString zone, mZone) {
//                sensor.m_Zones.append(zone.toInt());
//            }
//
//            if(mSection == "ems") {
//                sensor.m_Devices.append(QSrvMsgSecSensor::DeviceEMS);
//                //sensor.m_Zones.append(QSrvMsgSecSensor::DeviceEMS);
//            }
//            sensor.m_AptAddr = mDongho;
//            sensor.m_AlarmKey = mAlarmkey;
//
//            if(mDebugMsg)
//                qDebug() << sensor;
//
//            if(!sensor.m_AptAddr.isEmpty()) {
//                ComplexClient::instance()->qdbusSensor->NotifySensorEvent(sensor);
//            }
//            //
//            // send response to the server
//            //
//            QString body = QString("#dongho=%1").arg(mDongho);
//            body += QString("alarmkey=%1").arg(mAlarmkey);
//            QString request = header.createMessage(Xcp.TARGET__ALARM, Xcp.CMD__EVENT_RSP, body);
//            ComplexClient::instance()->sendToServer(request);
//
//            return true;
//        }
//        else if(header.mCmdType == Xcp.CMD__QUERY_REQ) {
//            //
//            //	response
//            //
//            ComplexClient::instance()->qdbusSensor->SendSensorRsp(header.mCopy);
//            return true;
//        }
//        else if(header.mCmdType == Xcp.CMD__QUERY_RSP) {
//
//            QString mSection = MsgUtil::parseBody(message, "#section=");
//            if(mSection == "history") {
//                QString mMode= MsgUtil::parseBody(message, "#mode=");
//                QStringList mNo= MsgUtil::parseBodyList(message, "#no=");
//                QStringList mOnOff= MsgUtil::parseBodyList(message, "#onoff=");
//                QStringList mAlarm= MsgUtil::parseBodyList(message, "#alarm=");
//                QStringList mZone= MsgUtil::parseBodyList(message, "#zone=");
//                QStringList mDonghoList = MsgUtil::parseBodyList(message, "#dongho=");
//                QStringList mAlarmkeyList =  MsgUtil::parseBodyList(message, "#alarmkey=");
//
//                QSrvMsgSecSensor sensor;
//                sensor.m_Address = QString("%1&%2").arg(header.mDong).arg(header.mHo);
//                sensor.m_Command = QString::number((int)header.mCmdType);
//                sensor.m_Copy = header.mCopy;
//                sensor.m_Version = header.mVersion;
//
//                sensor.m_Mode = mMode;
//                foreach(QString no, mNo) {
//                    sensor.m_Devices.append(no.toInt());
//                }
//                foreach(QString onoff, mOnOff) {
//                    sensor.m_Status.append(onoff.toInt() > 0 ? true:false);
//                }
//                foreach(QString alarm, mAlarm) {
//                    sensor.m_Alarms.append(alarm.toInt());
//                }
//                foreach(QString zone, mZone) {
//                    sensor.m_Zones.append(zone.toInt());
//                }
//
//                sensor.m_AptAddrList = mDonghoList;
//                sensor.m_AlarmKeyList = mAlarmkeyList;
//
//                ComplexClient::instance()->qdbusSensor->NotifySensorEvent(sensor);
//
//            }
//        }
        return true;
    }

    public boolean sample_req_Q_ELECAR_charger(int start, int end) {
        /*
        1. 충전소 및 충전기 상태 조회
        - 요청 [월패드 -> 단지서버]
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=elecar#mode=charger
        #param=1&5

        - 응답 [단지서버-> 월패드]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=elecar#mode=charger
        #param=1&5
        #total=1
        #no=1
        #stationid=1
        #station_loc=107 동 지하 충전소
        #station_info=1,충전대기&2,충전시작

        - 오류[단지서버-> 월패드]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=elecar#mode=car
        #dongho=101&201
        #param=1&5
        #err=0001&nodata
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__ELECAR);
		req.setBodyValue("mode", "charger" );
		req.setBodyValue("param", Xcp.make_range(start, end) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("total");
            rsp.bodyValueTable("no", "stationid", "station_loc", "station_info");
            // do something
        });
	}

    /**
     *
     * @param from yyyyMMdd
     * @param to yyyyMMdd
     * @return
     */
    public boolean sample_req_Q_ELECAR_use(String from, String to) {
        /*
        2. 사용 이력 조회 [상태 조회]
        - 요청 [홈서버 -> 단지서버]
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=elecar#mode=use
        #dongho=101&201
        #param=20161001&20161031

        - 응답 [단지서버 -> 홈서버]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=elecar#mode=use
        #dongho=101&201
        #param=20161001&20161031
        #total=2
        #no=1
        #station_id=1
        #charger_id=2
        #usestart=20100802132901
        #useend=20100802152901
        #usetime=2
        #usage=200
        #fee=10000
        #no=2
        #station_id=1
        #chager_id=2
        #usestart=20100802132901
        #useend=20100802152901
        #usetime=2
        #usage=200
        #fee=10000

        - 오류
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=elecar#mode=use
        #dongho=101&201
        #param=20161001&20161031
        #err=0001&nodata
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__ELECAR);
		req.setBodyValue("mode", "use" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("param", Xcp.join_amp(from, to) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("total");
            rsp.bodyValueTable("no"
                , "station_id"
                , "charger_id"
                , "usestart"
                , "useend"
                , "usetime"
                , "fee"
            );
            // do something
        });
	}


    public boolean sample_req_Q_ELECAR_price() {
        /*
        3. 사용 가격 조회
        - 요청 [홈서버 -> 단지서버]
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=elecar#mode=price

        - 응답 [단지서버 -> 홈서버]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=elecar#mode=price
        #total=3
        #no=1
        #chargetype=1
        #regdate =201610231111
        #pricelist=10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10
        #no=2
        #chargetype=2
        # regdate =201610231111
        #pricelist=10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10
        #no=3
        #chargetype=3
        # regdate =201610231111
        #pricelist=10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10

        - 오류
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=elecar#mode=price
        #err=0001&nodata
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__ELECAR);
		req.setBodyValue("mode", "price" );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("total");
            rsp.bodyValueTable("no"
                , "chargetype"
                , "regdate"
                , "pricelist"
            );
            // do something
        });
	}

	boolean on_req_ELECAR(XcpMessage req) {

        if ( req.is_EVENT_REQ() ) {
            /*
            4. 충전 이벤트 전송
            - 요청 [단지서버->월패드]
            <start=0000&0>$version=2.0$cmd=30$dongho=100&601$target=elecar
            #mode=event
            #station_id=10
            #station_loc=105 동 충전소
            #chargerid=2
            #dongho=101&201
            #cardno=
            #carno=2321
            #usestart=20160704153000
            #useend=20160704173000
            #usage=300
            #fee=15000
            #state=충전중지,오류없음

            - 응답 [단지서버 -> 월패드]
            <start=0000&0>$version=2.0$cmd=31$dongho=100&401$target=elecar#mode=event
            #dongho=101&201
            */
            if ( req.bodyValue("mode").equals("event")) {

                doNotify(req);

//                XcpMessage rsp = newResponse(req);
//                rsp.setBodyValue("mode", "event");
//                return sendMessage(rsp);
                return ElectricCarMessage.onReceived(req);
            }
        }
        return false;
    }

    /*
    1. 헬스 연동 사용자 조회
    2. 헬스 연동 사용자 인증 요청
    2. main 정보
    3. 혈압
    4. 체성분
    5. 비만
    6. 부위별 비만
     */
    public boolean sample_req_Q_HEALTH_user(int start, int end) {
        /*
        1. 헬스 연동 사용자 조회
        - 요청 [월패드 -> 단지서버]
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=health#mode=user
        #dongho=101&201
        #param=1&5

        - 응답 [단지서버-> 월패드]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=health#mode=user
        #dongho=101&201
        #param=1&5
        #no=1
        # id=1111
        #no=2
        # id=1112

        - 오류[단지서버-> 월패드]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=health#mode=user
        #dongho=101&201
        #param=1&5
        #err=0001&nodata
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__HEALTH);
		req.setBodyValue("mode", "user" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("param", Xcp.make_range(start, end) );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("total");
            rsp.bodyValueTable("no", "id");
            // do something
        });
	}

    public boolean sample_req_Q_HEALTH_auth(String id) {
        /*
        2. 헬스 연동 사용자 인증 요청
        - 요청 [월패드 -> 단지서버]
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=health#mode=auth
        #dongho=101&201
        #id=1111

        - 응답 [단지서버-> 월패드]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=health#mode=auth
        #dongho=101&201
        #id=1111
        #res=ok

        - 오류[단지서버-> 월패드]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=health#mode=auth
        #dongho=101&201
        #id=1111
        #res=faile
        #err=0001&nodata
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__HEALTH);
		req.setBodyValue("mode", "auth" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("id", id );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("res").equals("ok");
            // do something
        });
	}


    public boolean sample_req_Q_HEALTH_main(String id) {
        /*
        2. main 정보
        - 요청 [월패드-> 단지서버]
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=health#mode=main
        #dongho=101&201
        #id=1111

        - 응답 [단지서버 -> 홈서버]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=health#mode=main
        #dongho=101&201
        #id=1111
        #checkdate =20160805120000
        #pressure=140,80
        #wt=100,80.50
        #smm=33.1,29.2,45.6
        #bfm=25.76,8.2,16.3
        #bmi=20.0,18.5,23
        #pbf=30.9,10.20
        #whr=0.87,0.8,0.9
        #vfa=10

        - 오류
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=health#mode=main
        #dongho=101&201
        #id=1111
        #err=0001&nodata
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__HEALTH);
		req.setBodyValue("mode", "main" );
		req.setBodyValue("dongho", makeDongHo() );
		req.setBodyValue("id", id );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValue("checkdate");
            rsp.bodyValue("pressure");
            rsp.bodyValue("wt");
            rsp.bodyValue("smm");
            //...
            // do something
        });
	}

    /*
    10 공기질 조회 서비스 연동  target=aircondition
        1. 기기 조회
        2. 공기질 상태 조회
        3. 공기질 상태 조회 (옥외)
     */
    public boolean sample_req_Q_AIRCONDITION_device_list() {
        /*
        1. 기기 조회
        - 요청 [월패드 -> 단지서버]
        <start=0000&0>$version=2.0$cmd=10$dongho=101&201$target=aircondition
        #mode=device_list
        #dongho=101&201

        - 응답 [단지서버-> 월패드]
        <start=0000&0>$version=2.0$cmd=11$dongho=101&201$target=aircondition
        #mode=device_list
        #dongho=101&201
        #no=1
        #device_type=1111
        #device_id=
        #device_name=
        #space_type=
        #location_name=
        #latinude=
        #logngitude=
        #owner_type=
        #no=2
        */
		XcpMessage req = newRequest(Xcp.CMD__QUERY_REQ, Xcp.TARGET__AIRCONDITION);
		req.setBodyValue("mode", "device_list" );
		req.setBodyValue("dongho", makeDongHo() );
		return request(req, (reply)-> {
		    if ( !reply.isOk() )
		        return;

		    String err = reply.response().bodyValue("err");
            if ( !err.isEmpty() ) {
                // error
                return;
            }

            XcpMessage rsp = reply.response();
            rsp.bodyValueTable("no"
                , "device_type"
                , "device_id"
                , "device_name"
                , "space_type"
                    //...
            );
            // do something
        });
	}
        /*
        device

            REQ:
                <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=gasvalve#no=0
            RSP:
                <start=0000&0>$version=2.0$copy=00-
                0000$cmd=11$dongho=101&201$target=device#mode=control#targetname=gasvalve
                #no=1
                #kname=주방
                #ename=kichen
        */

        /*
        #mode=menu_lst :스펙 상 연동하는 메뉴 리스트
        #mode=control_lst : 스펙 상 연동하는 제어 리스트
        #mode=control : 각 제어 기기 명칭 정보
         */
    boolean on_req_DEVICE(XcpMessage req) {

        if ( req.is_QUERY_REQ() ) {

            String mode = req.bodyValue("mode");
            switch (mode) {
                case "menu_lst": {
                /*
                1.메뉴 기기 리스트 조회(전체 조회)
                - 조회 요청
                월패드 스펙 중 연동하는 메뉴 ( iconlist) 의 목록 조회
                <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=device
                #mode=menu_lst

                - 조회 응답
                <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=device
                #mode=menu_lst
                #no=1#kname=인터폰#ename=interphone#option=
                #no=2#kname=전화#ename=phone#option=
                #no=3#kname=현관보기#ename=F.Door#option=
                #no=4#kname=통화기록#ename=C.History#option=
                #no=5#kname=방문자목록#ename=visitors#option=
                #no=6#kname=조명#ename=light#option=
                #no=7#kname=가스#ename=gas#option=
                #no=8#kname=난방#ename=heating#option=
                #no=9#kname=대기전력#ename=SB.Power#option=

                ------------------------------------------
                mode=menu_lst 응답은 <iconlist> 에서 use="true" 인것만 골라서 보낸다
                */

                    XcpMessage rsp = newResponse(req);
                    rsp.setBodyValue("mode", "menu_lst");

                    XcpSpec.DevArray array = sXmlSpec.getDevArrayByPayloadValue("iconlist");
                    if (array == null) {
                        PtLog.i(TAG, "unexpected array==null");
                        rsp.setBodyValue("err", Xcp.ERR__NO_DEVICE);
                        return sendMessage(rsp);
                    }
                    //#dh00000116 target=device, mode=menu_lst 응답(11) #Redmine질의 #1438 대로 수정
                    /*
                     * 기본적으로 spec 파일의 내용만 보낸다. 또한 use = true 인 것들만 사용함.
                     * no 값은 server_no 사용.
                     */
//                int no = 0;
                    List<XcpSpec.DevItem> iconList = array.arrays.payload.iconlist_list;
                    for (XcpSpec.DevItem item : iconList) {
                        if (item.use.equals("true")) {
//                        rsp.addBodyValue("no", ++no);
                            rsp.addBodyValue("no", item.getServerNo());
//                        rsp.addBodyValue("server_no", item.getServerNo());
//                        rsp.addBodyValue("targetname", "light");
                            rsp.addBodyValue("kname", item.name);
                            rsp.addBodyValue("ename", item.name_eng);
                            rsp.addBodyValue("option", item.option);
                        }
                    }
                    return sendMessage(rsp);
                }
                case "control_lst": {
                /*
                2.제어 기기 리스트 조회(전체 조회)
                - 조회 요청
                월패드 스펙 중 연동하는 제어 기기의 목록 조회
                <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=device
                #mode=control_lst

                - 조회 응답
                <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=device
                #mode=control_lst
                #no=1#targetname=alllight#kname=일괄조명#ename=batch
                #no=2#targetname=light#kname=조명#ename=batch
                #no=3#targetname=gas#kname=가스#ename=batch
                #no=4#targetname=boiler#kname=온도#ename=batch
                #no=5#targetname=standby#kname=대기전력#ename=batch
                #no=6#targetname=curtain#kname=커튼#ename=batch
                #no=7#targetname=airfan#kname=환기#ename=batch
                #no=8#targetname=aircon#kname=에어컨#ename=batch
                #no=9#targetname=acs#kname=시스클라인#ename=batch

                - 에러
                <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=device
                #mode=control_lst
                #err=0001&not found specification

                --------------------------------
                mode=control_lst 응답은 <iconlist> 에서 use="true" 인것 중에서, server_no=6, 7, 8, 9, 10, 11, 12 인것만 골라서 보낸다
                단, server_no=6 가 존재할 경우, alllight 일괄조명을 추가하여 보낸다 ( MAX 8개 )
                단지서버 문서에 있는, meter, subphone 은 보내지 않는다. ( 단지서버 문서에는 MAX 10개 )
                ---------------------------------
                1) control_lst 응답 : MAX 9개 ( meter, subphone 필요없슴 )
                alllight, light, gas, boilder, stanby,
                curtain, airfan, aircon, acs
                 */
                    XcpMessage rsp = newResponse(req);
                    if (rsp != null) {
                        rsp.setBodyValue("mode", "control_lst");

                        XcpSpec.DevArray array = sXmlSpec.getDevArrayByPayloadValue("iconlist");
                        if (array == null) {
                            PtLog.i(TAG, "unexpected array==null");
                            rsp.setBodyValue("err", Xcp.ERR__NO_DEVICE);
                            return sendMessage(rsp);
                        }

                        boolean isAcs = false;
                        int no = 0;
                        List<XcpSpec.DevItem> iconList = array.arrays.payload.iconlist_list;

                        // begin CJH 2021-06-23 : 메뉴 아이콘 정렬('iconlist'의 'server_no' 기준)
                        Collections.sort(iconList, new Comparator<XcpSpec.DevItem>() {
                            @Override
                            public int compare(XcpSpec.DevItem o1, XcpSpec.DevItem o2) {
                                return Integer.compare(Integer.parseInt(o1.getServerNo(), 16), Integer.parseInt(o2.getServerNo(), 16));
                            }
                        });
                        // end CJH 2021-06-23

                        // 시스클라인 있으면 환기를 iconlist에서 빼야함
                        for (XcpSpec.DevItem item : iconList) {
                            if (item.getServerNo().equals("53") && item.use.equals("true")) isAcs = true;
                        }

                        for (XcpSpec.DevItem item : iconList) {
                            if (item.getServerNo().equals("6") && item.use.equals("true")) {
                                // add "alllight"
                                rsp.addBodyValue("no", ++no);
                                rsp.addBodyValue("targetname", "alllight"); //#dh00000117 target=device, mode=control_lst 응답(11) 오타 수정
                                rsp.addBodyValue("kname", "일괄조명");
                                rsp.addBodyValue("ename", "lightall");

                                // add "light"
                                rsp.addBodyValue("no", ++no);
                                rsp.addBodyValue("targetname", "light");
                                rsp.addBodyValue("kname", item.name);
                                rsp.addBodyValue("ename", item.name_eng);
                            } else if (item.getServerNo().equals("7") && item.use.equals("true")) {//#dh00000117 target=device, mode=control_lst 응답(11) 오타 수정
                                rsp.addBodyValue("no", ++no);
                                rsp.addBodyValue("targetname", "gasvalve");
                                rsp.addBodyValue("kname", item.name);
                                rsp.addBodyValue("ename", item.name_eng);

                                ProxyPojo.GasMap gasvalve_map = ProxyServer.getGasMap();
                                if(gasvalve_map.isHybrid()) {
                                    rsp.addBodyValue("device_type", "hybrid");
                                } else if (gasvalve_map.isCookTop()) {
                                    rsp.addBodyValue("device_type", "cooktop");
                                } else {
                                    rsp.addBodyValue("device_type", "gas");
                                }
                                // gasvalve는 쿡탑, 하이브리드, 일반 가스차단기에 따라 #device_type에 gas, hybrid, cooktop 기입
                            /*if(item.option.equals("2"))
                                rsp.addBodyValue("device_type", "hybrid");
                            else if(item.option.equals("3"))
                                rsp.addBodyValue("device_type", "cooktop");
                            else
                                rsp.addBodyValue("device_type", "gas");*/
                            } else if (item.getServerNo().equals("8") && item.use.equals("true")) {
                                rsp.addBodyValue("no", ++no);
                                rsp.addBodyValue("targetname", "boiler");
                                rsp.addBodyValue("kname", item.name);
                                rsp.addBodyValue("ename", item.name_eng);
                            } else if (item.getServerNo().equals("9") && item.use.equals("true")) {
                                rsp.addBodyValue("no", ++no);
                                rsp.addBodyValue("targetname", "standby");
                                rsp.addBodyValue("kname", item.name);
                                rsp.addBodyValue("ename", item.name_eng);
                            } else if (item.getServerNo().equals("10") && item.use.equals("true")) {
                                rsp.addBodyValue("no", ++no);
                                rsp.addBodyValue("targetname", "curtain");
                                rsp.addBodyValue("kname", item.name);
                                rsp.addBodyValue("ename", item.name_eng);
                            } else if (item.getServerNo().equals("11") && item.use.equals("true")) {
                                if (!isAcs) {
                                    rsp.addBodyValue("no", ++no);
                                    rsp.addBodyValue("targetname", "airfan");
                                    rsp.addBodyValue("kname", item.name);
                                    rsp.addBodyValue("ename", item.name_eng);
                                }
                            } else if (item.getServerNo().equals("12") && item.use.equals("true")) {
                                rsp.addBodyValue("no", ++no);
                                rsp.addBodyValue("targetname", "aircon");
                                rsp.addBodyValue("kname", item.name);
                                rsp.addBodyValue("ename", item.name_eng);
                            } else if (item.getServerNo().equals("53") && item.use.equals("true")) {
                                rsp.addBodyValue("no", ++no);
                                rsp.addBodyValue("targetname", "acs");
                                rsp.addBodyValue("kname", item.name);
                                rsp.addBodyValue("ename", item.name_eng);
                            }
                        }
                    }

                    return sendMessage(rsp);
                }
                case "control": {

                    List<String> korRoomNames = new ArrayList<>();
                    List<String> engRoomNames = new ArrayList<>();
                /*
                3.제어 기기 조회
                - 조회 요청
                월패드 스펙 중 연동하는 제어 기기의 위치별, device 별 조회
                주) 본 예제에서의 #no= 및 #device_no= 실제 제어 위치 및 존과 일치해야함.

                조명 조회 요청
                <start=0000&0>$version=2.0$copy=00-0000$cmd=10$dongho=101&201$target=device
                #mode=control#targetname=light

                - 조회 응답
                <start=0000&0>$version=2.0$copy=00-
                0000$cmd=11$dongho=101&201$target=device
                #mode=control#targetname=light
                #device_mode=sub
                #no=1
                #kname=거실
                #ename=living
                #device_no=1
                #kname=조명 1
                #ename=light1
                #devcie_no=2
                #kname=조명 2
                #ename=light2
                #no=2
                #kname=방 1
                #ename=living
                #device_no=1
                #kname=방조명 1
                #ename=light1
                #devcie_no=2
                #kname=방조명 2
                #ename=light2

                - 에러( 공통 )
                <start=0000&0>$version=2.0$copy=00-0000$cmd=11$dongho=101&201$target=device
                #mode=control#targetname=[해당 target]
                #err=0001&not found specification
                 */
                    XcpMessage rsp = newResponse(req);
                    rsp.setBodyValue("mode", "control");

                /*XcpSpec.DevArray array = sXmlSpec.getDevArrayByPayloadValue("iconlist");
                if ( array == null ) {
                    PtLog.i(TAG, "unexpected array==null" );
                    rsp.setBodyValue("err", Xcp.ERR__NO_DEVICE);
                    return sendMessage(rsp);
                }*/

                    //#dh00000118 target=device, mode=control 응답(11) 추가. (#redmine 1438 참고)
                    /**
                     * no - 방번호, device_no - 방에 있는 디바이스번호
                     * 2) control, targetname : 최대 9 개
                     * [alllight, light, gas, boilder, stanby, curtain, airfan, aircon, acs]
                     * [일괄, 조명, 가스, 온도조절기, 대기전력, 환기, 에어컨, 시스클라인]
                     */
                    int index = 1; // index starting from 1
                    String targetName = req.bodyValue("targetname");
                    rsp.setBodyValue("targetname", targetName);

                    switch (targetName) {
                        case Xcp.TARGET__ALLLIGHT:
                            XcpSpec.DevArray batchBreaker = sXmlSpec.getDevArrayByPayloadValue("light");
                            if (batchBreaker == null) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }
                            List<XcpSpec.DevItem> allLightList = batchBreaker.arrays.payload.light_list;
                            if(allLightList.size() == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }
                            for (XcpSpec.DevItem item : allLightList) {
                                if (item.device_id.equals("33") || item.device_id.equals("63")) { // 210416 CJH SID addr 추가
                                    if (item.use.compareToIgnoreCase("true") == 0) {
                                        rsp.addBodyValue("no", index++/*item.getServerNo()*/);
                                        rsp.addBodyValue("kname", item.name);
                                        rsp.addBodyValue("ename", item.name_eng);
                                    }
                                }
                            }
                            break;
                        case Xcp.TARGET__LIGHT:
                            XcpSpec.DevArray lightArray = sXmlSpec.getDevArrayByPayloadValue("light");
                            if (lightArray == null) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }
                            List<XcpSpec.DevItem> lightList = lightArray.arrays.payload.light_list;
                            if(lightList.size() == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }

                            for (XcpSpec.DevItem item : lightList) {
                                if (item.device_id.compareToIgnoreCase("0E")==0) {
                                    korRoomNames.add(item.name);
                                    engRoomNames.add(item.name_eng);
                                }
                            }

                            rsp.setBodyValue("device_mode", "sub");
                            ProxyPojo.LightMap light_map = ProxyServer.getLightMap();
                            int lightIndex = 0; index = 0;
                            try {
                                for(int sub_id : light_map.keySet()) {
                                    TtaXiLight light = light_map.get(sub_id);
                                    if (light.m_discovered) {
                                        // 210806 CJH lightIndex(임의값) 이 아닌 실제 디바이스 sub_id 를 전달한다.
                                        //            비트 연산을 통해 단지서버에 전달할 'server_no'를 구한다.
                                        //            11 -> 1, 12 -> 2, 1A -> 10
//                                        rsp.addBodyValue("no", lightIndex + 1);
                                        rsp.addBodyValue("no", sub_id & 0x0F);
                                        rsp.addBodyValue("kname", korRoomNames.get(index));
                                        rsp.addBodyValue("ename", engRoomNames.get(index));
                                        for (int j = 0; j < light.status.size(); j++) {
                                            rsp.addBodyValue("device_no", j + 1);
                                            //rsp.addBodyValue("kname", String.format(Locale.getDefault(), "%d.조명", j + 1));
                                            //rsp.addBodyValue("ename", String.format(Locale.getDefault(), "%d.light", j + 1));
                                            if (light.status.get(j) != null) {
                                                // 20210217 devtype에 조명 타입 추가
                                                // begin kyeongilhan 2021-09-13 : 조명 타입에 따라 리턴하는 조명 이름 다양화
                                                // 485mst property에 따라 none, dimming, clrtemp, all 로 구분
                                                if (light.status.get(j).b_color_type == 1) {
                                                    if (light.status.get(j).b_dimming_type == 1) {
                                                        rsp.addBodyValue("kname", String.format(Locale.getDefault(), "%d.감성조명", j + 1));
                                                        rsp.addBodyValue("ename", String.format(Locale.getDefault(), "%d.emotion", j + 1));
                                                        rsp.addBodyValue("device_type", "all");
                                                    } else {
                                                        rsp.addBodyValue("kname", String.format(Locale.getDefault(), "%d.색온도", j + 1));
                                                        rsp.addBodyValue("ename", String.format(Locale.getDefault(), "%d.colorTemp", j + 1));
                                                        rsp.addBodyValue("device_type", "clrtemp");
                                                    }
                                                } else if (light.status.get(j).b_dimming_type == 1) {
                                                    rsp.addBodyValue("kname", String.format(Locale.getDefault(), "%d.디밍", j + 1));
                                                    rsp.addBodyValue("ename", String.format(Locale.getDefault(), "%d.dimming", j + 1));
                                                    rsp.addBodyValue("device_type", "dimming");
                                                } else {
                                                    rsp.addBodyValue("kname", String.format(Locale.getDefault(), "%d.조명", j + 1));
                                                    rsp.addBodyValue("ename", String.format(Locale.getDefault(), "%d.light", j + 1));
                                                    rsp.addBodyValue("device_type", "none");
                                                }
                                            } else {
                                                rsp.addBodyValue("kname", String.format(Locale.getDefault(), "%d.조명", j + 1));
                                                rsp.addBodyValue("ename", String.format(Locale.getDefault(), "%d.light", j + 1));
                                                rsp.addBodyValue("device_type", "none");
                                            }
                                        }
                                        lightIndex++;
                                    }
                                    index++;
                                }
                            }
                            catch(Exception e) {
                                e.printStackTrace();
                            }
                            if(lightIndex == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                            }
                            break;
                        case Xcp.TARGET__GASVALVE:
                            XcpSpec.DevArray gasArray = sXmlSpec.getDevArrayByPayloadValue("gas");
                            if (gasArray == null) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }
                            List<XcpSpec.DevItem> gasList = gasArray.arrays.payload.gas_list;
                            if(gasList.size() == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }

                            for (XcpSpec.DevItem item : gasList) {
                                korRoomNames.add(item.name);
                                engRoomNames.add(item.name_eng);
                            }

                            index = 0;
                            int seqNo = 0;
                            ProxyPojo.GasMap gasvalve_map = ProxyServer.getGasMap();

                            if(gasvalve_map.isHybrid()) rsp.addBodyValue("device_mode", "sub");

                            for (Map.Entry<Integer, TtaXiGas> entry : gasvalve_map.entrySet()) {
                                TtaXiGas dev = entry.getValue();
                                if (dev.m_discovered) {
                                    if(gasvalve_map.isHybrid()) {
                                        rsp.addBodyValue("no", seqNo+1);
                                        rsp.addBodyValue("kname", korRoomNames.get(0));
                                        rsp.addBodyValue("ename", engRoomNames.get(0));
                                        int k=0;
                                        while (k<2) {

                                            // 20210526 가스 device_no 누락 수정
                                            rsp.addBodyValue("device_no", k+1);

                                            if (k==0) {
                                                rsp.addBodyValue("kname", "1.가스");
                                                rsp.addBodyValue("ename", "1.gas");
                                                rsp.addBodyValue("device_type", "gas" );
                                            }
                                            else {
                                                rsp.addBodyValue("kname", "2.쿡탑");
                                                rsp.addBodyValue("ename", "2.cooktop");
                                                rsp.addBodyValue("device_type", "cooktop" );
                                            }
                                            k++;
                                        }
                                    } else {
                                        rsp.addBodyValue("no", seqNo+1);

                                        // begin kyeongilhan 2021-06-15 : 가스나 쿡탑만 있을 경우 kname,ename 잘못가는 현상 수정
                                        if(dev.property.b_cooktop == 1) {
                                            rsp.addBodyValue("kname", korRoomNames.get(0));
                                            rsp.addBodyValue("ename", engRoomNames.get(0));
                                            rsp.addBodyValue("device_type", "cooktop" );
                                        }
                                        else {
                                            rsp.addBodyValue("kname", korRoomNames.get(0));
                                            rsp.addBodyValue("ename", engRoomNames.get(0));
                                            rsp.addBodyValue("device_type", "gas" );
                                        }
                                        // end kyeongilhan 2021-06-15
                                    }
                                    index++;
                                }
                                seqNo++;
                            }
                            if(index == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                            }

                            /*if(gasvalve_map.isHybrid())
                                rsp.setBodyValue("device_mode", "sub");
                            int valveIndex = 0; index = 0;
                            for(int sub_id : gasvalve_map.keySet()) {
                                TtaXiGas gasValve = gasvalve_map.get(sub_id);
                                if(gasValve.m_discovered) {
                                    if(gasvalve_map.isHybrid()) {
                                        rsp.addBodyValue("device_no", valveIndex+1);
                                    } else {
                                        rsp.addBodyValue("no", valveIndex+1);
                                    }

                                    rsp.addBodyValue("kname", korRoomNames.get(index));
                                    rsp.addBodyValue("ename", engRoomNames.get(index));
                                    rsp.addBodyValue("device_type", gasValve.property.b_cooktop==1 ? "cooktop" : "gas");
                                    valveIndex++;
                                }
                                index++;
                            }
                            if(valveIndex == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                            }*/
                            break;
                        case Xcp.TARGET__BOILER:

                            try {

                                XcpSpec.DevArray tempArray = sXmlSpec.getDevArrayByPayloadValue("temp");
                                if (tempArray == null)
                                    break;
                                List<XcpSpec.DevItem> tempList = tempArray.arrays.payload.temp_list;
                                if(tempList.size() == 0) {
                                    rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                    break;
                                }
                                for (XcpSpec.DevItem item : tempList) {
                                    korRoomNames.add(item.name);
                                    engRoomNames.add(item.name_eng);
                                }

                                ProxyPojo.ThermostatMap boilerMap = ProxyServer.getThermostatMap();
                                int i=0;
                                index = 0;
                                for (Map.Entry<Integer, ProxyPojo.Thermostat> entry : boilerMap.entrySet()) {
                                    Integer id = entry.getKey();
                                    ProxyPojo.Thermostat thermostat = entry.getValue();
                                    if (thermostat.discovered) {
                                        if (!(index >= korRoomNames.size())) {
                                            rsp.addBodyValue("no", DevBoilerMessage.getRoomIndex(id));
                                            rsp.addBodyValue("kname", korRoomNames.get(index));
                                            rsp.addBodyValue("ename", engRoomNames.get(index));
                                        }
                                        index++;
                                    } else {
                                        if (!(index >= korRoomNames.size())) {
                                            rsp.addBodyValue("no", index+1);
                                            rsp.addBodyValue("kname", korRoomNames.get(index));
                                            rsp.addBodyValue("ename", engRoomNames.get(index));
                                        }
                                        index++;
                                    }
                                }
                                if(index == 0) {
                                    rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                }
                            } catch (Exception e) {
                                Log.d(TAG, Log.getStackTraceString(e));
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                            }



                            /*for (XcpSpec.DevItem item : tempList) {
                                if (item.use.compareToIgnoreCase("true")==0) {
                                    rsp.addBodyValue("no", index++*//*item.getServerNo()*//*);
                                    rsp.addBodyValue("kname", item.name);
                                    rsp.addBodyValue("ename", item.name_eng);
                                }
                            }*/
                            break;
                        case Xcp.TARGET__STANDBYPWR:
                            XcpSpec.DevArray stdbypwrArray = sXmlSpec.getDevArrayByPayloadValue("stdbypwr");
                            if (stdbypwrArray == null)
                                break;
                            List<XcpSpec.DevItem> stdbyList = stdbypwrArray.arrays.payload.stdbypwr_list;
                            if(stdbyList.size() == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }
                            for (XcpSpec.DevItem item : stdbyList) {
                                korRoomNames.add(item.name);
                                engRoomNames.add(item.name_eng);
                            }

                            // begin kyeongilhan 2023-02-06 : no=7,8 주방 디바이스의 대기전력 이름 구분 추가
                            int langIndex = HaSpec.languageIndex();
                            int kitchen = 0;
                            int totalKitchen = 0;

                            for (int subId : ProxyServer.getStdPwrMap().keySet()) {
                                HaSpec.DevAtomicItem specItem = HaSpec.getStbypwrBrkSpecItem(subId);
                                if (specItem != null) {
                                    if (specItem.devItem.names.get(langIndex).equals(getString(R.string.s02__sp_kitchen))) totalKitchen++;
                                }
                            }

                            rsp.setBodyValue("device_mode", "sub");
                            ProxyPojo.StbyPwrBrkMap stbyPwrBrkMap = ProxyServer.getStdPwrMap();
                            ProxyPojo.XiStbyPwrBrkMap xiStbyPwrBrkMap = ProxyServer.getStdPwrXiMap();
                            int devIndex = 0; index = 0;

                            if(stbyPwrBrkMap.size() > 0) {
                                for(int sub_id : stbyPwrBrkMap.keySet()) {
                                    TtaXiStbyPwrBrk stbyPwrBrk = stbyPwrBrkMap.get(sub_id);
                                    HaSpec.DevAtomicItem specItem = HaSpec.getStbypwrBrkSpecItem(sub_id);

                                    if(stbyPwrBrk.m_discovered) {

                                        if (!stbyPwrBrk.drvId.equals("")) {
                                            // 210806 CJH lightIndex(임의값) 이 아닌 실제 디바이스 sub_id 를 전달한다.
                                            //            비트 연산을 통해 단지서버에 전달할 'server_no'를 구한다.
                                            //            1F -> 1, 2F -> 2, AF -> 10
//                                            String restr = stbyPwrBrk.drvId.replaceAll("[^0-9]","");
//                                            rsp.addBodyValue("no", Integer.parseInt(restr));
                                            rsp.addBodyValue("no", (sub_id & 0xF0) >> 4);
                                            rsp.addBodyValue("kname", korRoomNames.get(index));
                                            rsp.addBodyValue("ename", engRoomNames.get(index));
                                            for (int j=0; j < stbyPwrBrk.status.size(); j++) {

                                                if ((totalKitchen > 1) && (specItem.devItem.names.get(langIndex).equals(getString(R.string.s02__sp_kitchen)))) {
                                                    if (kitchen == 0) {
                                                        rsp.addBodyValue("device_no", j+1);
                                                        rsp.addBodyValue("kname", String.format(Locale.getDefault(), "%d.대기", j+1));
                                                        rsp.addBodyValue("ename", String.format(Locale.getDefault(), "%d.standby", j+1));
                                                    }
                                                    else if (kitchen == 1) {
                                                        rsp.addBodyValue("device_no", j+1);
                                                        rsp.addBodyValue("kname", String.format(Locale.getDefault(), "%d.대기", j+2));
                                                        rsp.addBodyValue("ename", String.format(Locale.getDefault(), "%d.standby", j+2));
                                                    }
                                                    kitchen++;
                                                } else {
                                                    rsp.addBodyValue("device_no", j+1);
                                                    rsp.addBodyValue("kname", String.format(Locale.getDefault(), "%d.대기", j+1));
                                                    rsp.addBodyValue("ename", String.format(Locale.getDefault(), "%d.standby", j+1));
                                                }
                                                // end kyeongilhan 2023-02-06
                                            }
                                        } else {
//                                            rsp.addBodyValue("no", index+1);
                                            rsp.addBodyValue("no", (sub_id & 0xF0) >> 4);
                                            rsp.addBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                        }

                                        devIndex++;
                                    } else {
//                                        rsp.addBodyValue("no", index+1);
                                        rsp.addBodyValue("no", (sub_id & 0xF0) >> 4);
                                        rsp.addBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                    }

                                    index++;
                                }
                            }
                            else if(xiStbyPwrBrkMap.size() > 0) {
                                for(int sub_id : xiStbyPwrBrkMap.keySet()) {
                                    XiStbyPwrBrk stbyPwrBrk = xiStbyPwrBrkMap.get(sub_id);
                                    if(stbyPwrBrk.m_discovered) {
                                        rsp.addBodyValue("no", devIndex+1);
                                        rsp.addBodyValue("kname", korRoomNames.get(index));
                                        rsp.addBodyValue("ename", engRoomNames.get(index));
                                        for (int j=0; j < stbyPwrBrk.status.size(); j++) {
                                            rsp.addBodyValue("device_no", j+1);
                                            rsp.addBodyValue("kname", String.format(Locale.getDefault(), "%d.대기", j+1));
                                            rsp.addBodyValue("ename", String.format(Locale.getDefault(), "%d.standby", j+1));
                                        }
                                        devIndex++;
                                    }
                                    index++;
                                }
                            }
                            else {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                            }
                            if(devIndex == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                            }
                            break;
                        case Xcp.TARGET__CURTAIN:
                            XcpSpec.DevArray curtainArray = sXmlSpec.getDevArrayByPayloadValue("curtain");
                            if (curtainArray == null)
                                break;
                            List<XcpSpec.DevItem> curtainList = curtainArray.arrays.payload.curtain_list;
                            if(curtainList.size() == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }
                            for (XcpSpec.DevItem item : curtainList) {
                                if (item.use.compareToIgnoreCase("true")==0) {
                                    rsp.addBodyValue("no", index++/*item.getServerNo()*/);
                                    rsp.addBodyValue("kname", item.name);
                                    rsp.addBodyValue("ename", item.name_eng);
                                }
                            }
                            break;
                        case Xcp.TARGET__AIRFAN:
                            XcpSpec.DevArray ventArray = sXmlSpec.getDevArrayByPayloadValue("vent");
                            if (ventArray == null)
                                break;
                            List<XcpSpec.DevItem> ventList = ventArray.arrays.payload.vent_list;
                            if(ventList.size() == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }
                            for (XcpSpec.DevItem item : ventList) {
                                if (item.use.compareToIgnoreCase("true")==0) {
                                    rsp.addBodyValue("no", index++/*item.getServerNo()*/);
                                    rsp.addBodyValue("kname", item.name);
                                    rsp.addBodyValue("ename", item.name_eng);
                                }
                            }
                            break;
                        case Xcp.TARGET__AIRCON:
                            XcpSpec.DevArray airconArray = sXmlSpec.getDevArrayByPayloadValue("aircon");
                            if (airconArray == null)
                                break;
                            List<XcpSpec.DevItem> airconList = airconArray.arrays.payload.aircon_list;
                            if(airconList.size() == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }
                            for (XcpSpec.DevItem item : airconList) {
                                if (item.use.compareToIgnoreCase("true")==0) {
                                    // begin CJH 2021-06-44 : 에어컨 특성 상 빈방이 존재하기 때문에 spec의 정의된 'sub_id' 로 전달
                                    rsp.addBodyValue("no", item.sub_id);
                                    // end CJH 2021-06-14
                                    rsp.addBodyValue("kname", item.name);
                                    rsp.addBodyValue("ename", item.name_eng);
                                }
                            }
                            break;
                        case Xcp.TARGET__SYSCLEIN:
                            XcpSpec.DevArray fauArray = sXmlSpec.getDevArrayByPayloadValue("fau");
                            if (fauArray == null)
                                break;
                            List<XcpSpec.DevItem> syscleinList = fauArray.arrays.payload.sysclein_list;
                            if(syscleinList.size() == 0) {
                                rsp.setBodyValue("err", Xcp.ERR__CANNOT_CONNECT);
                                break;
                            }
                            // begin CJH 2023-04-24 : 연결 상태 고려하지 않고 스펙에 나열된 리스트 모두 전달
                            /*for (XcpSpec.DevItem item : syscleinList) {
                                korRoomNames.add(item.name);
                                engRoomNames.add(item.name_eng);
                            }

                            index=0;
                            ProxyPojo.XiSyscleinMap xiSyscleinMap = ProxyServer.getXiSysCleinMap();
                            if (xiSyscleinMap.size() > 0) {
                                for (int sub_id : xiSyscleinMap.keySet()) {
                                    XiSysclein sysclein = xiSyscleinMap.get(sub_id);
                                    if (sysclein.m_discovered) {
                                        if (!sysclein.drvId.equals("")) {
                                            int no = Integer.parseInt(sysclein.drvId.substring(sysclein.drvId.length()-1));
                                            rsp.addBodyValue("no", no);
                                            rsp.addBodyValue("kname", korRoomNames.get(index));
                                            rsp.addBodyValue("ename", engRoomNames.get(index));
                                        } else {
                                            rsp.addBodyValue("no", index+1);
                                            rsp.addBodyValue("kname", korRoomNames.get(index));
                                            rsp.addBodyValue("ename", engRoomNames.get(index));
                                        }
                                    } else {
                                        rsp.addBodyValue("no", index+1);
                                        rsp.addBodyValue("kname", korRoomNames.get(index));
                                        rsp.addBodyValue("ename", engRoomNames.get(index));
                                    }
                                    index++;
                                }
                            }*/

                            for (XcpSpec.DevItem item : syscleinList) {
                                if (item.use.compareToIgnoreCase("true")==0) {
                                    rsp.addBodyValue("no",    item.sub_id);
                                    rsp.addBodyValue("kname", item.name);
                                    rsp.addBodyValue("ename", item.name_eng);
                                }
                            }
                            // end CJH 2023-04-24
                            break;
                        default:
                            PtLog.i(TAG, "unexpected device query");
                            rsp.setBodyValue("err", "0001&not found specification");
                            rsp.setBodyValue("targetname", targetName);
                    }
                    return sendMessage(rsp);
                }
            }
        } else if ( req.is_CTRL_REQ() ) {
            // 비번 초기화 명령 (hidden)
            Log.d(TAG, "[hidden] password reset request!!!");
            LoginoutMessage.sendPasswordChangeRequest("1234", new LoginoutMessage.OnPwdChangedListener() {
                @Override
                public void response(boolean result) {
                    if (result) {
                        OliviaPref.getInstance().putString(OliviaPref.USER__PRIMARY_PASSWORD, DEFAULT_USER__PRIMARY_PASSWORD);
                        Log.d(TAG, "password reset success");
                        //Toast.makeText(, R.string.s10_04__pwd1_success_reset, Toast.LENGTH_SHORT).show();
                    } else {
                        Log.d(TAG, "password reset fail");
                        //Toast.makeText(getApplicationContext(), R.string.s10_04__pwd1_failed_to_reset, Toast.LENGTH_SHORT).show();
                    }
                }
            });

        }
        return false;
    }

    public boolean isSpecFileDownloaded() {
        if(mSpecFileDownloaded) {
            if (mSpecUpdated)
                return true;
        }
        return false;
    }

    /**
     * test
     */
    public static void test() {
        PtLog.i(TAG, "th:%s", Thread.currentThread() );

        HandlerThread handlerThread = new HandlerThread("XcpClientSession");
        handlerThread.start();

        XcpEngine xcm = new XcpEngine();
        xcm.connect(3, 1101, "192.168.10.240", Xcp.PORT);
    }

    private void pfxCertificationDownloaded(boolean result, Object userdata, String path) {
        String command = (String)userdata;

        // be careful.. this is not in main thread.
        Log.e(TAG, "downloading " + getMacAddress()+".pfx " + path + ", " + command);

        File file = new File(path);
        if (!file.exists()) {
            Log.e(TAG, "File does not exist.");
            return;
        }
        if (!(file.isFile() && file.canRead())) {
            Log.e(TAG, file.getName() + " cannot be read from.");
            return;
        }

        if(file.exists() && file.length() > 0) {
            Log.e(TAG, file.getAbsolutePath() + " download complete");
        }
    }

    private void tempCertificationDownloaded(boolean result, Object userdata, String path) {
        String command = (String)userdata;

        // be careful.. this is not in main thread.
        Log.e(TAG, "downloading temp cert result: " + path + ", " + command);

        if (result) {
            File file = new File(path);
            if (!file.exists()) {
                Log.e(TAG, "File does not exist.");
                return;
            }
            if (!(file.isFile() && file.canRead())) {
                Log.e(TAG, file.getName() + " cannot be read from.");
                return;
            }

            if(file.exists() && file.length() > 0) {
                Log.e(TAG, file.getAbsolutePath() + " download complete");
                certHandler.removeCallbacksAndMessages(null);
            }
        } else {
            Log.e(TAG, "temp cert download failed");
        }
    }

    private void specificationDownloaded(boolean result, Object userdata, String path) {


        if(userdata instanceof String) {
            String command = (String)userdata;

            // be careful.. this is not in main thread.
            Log.e(TAG, "downloading specification.xml result: " + result + ", " + path + ", " + command);

            if(result) {

                //load xml file to string
                StringBuilder total = new StringBuilder();
                String line;
                File file = new File(path);
                if (!file.exists()) {
                    Log.e(TAG, "File does not exist.");
                    return;
                }
                if (!(file.isFile() && file.canRead())) {
                    Log.e(TAG, file.getName() + " cannot be read from.");
                    return;
                }
                Log.e(TAG, "file downloaded = " + file.getAbsolutePath() + "[" + file.length() + "]");
                if(file.exists() && file.length() > 0) {
                    try {
                        InputStream stream = new FileInputStream(file);
                        //BufferedReader r = new BufferedReader(new InputStreamReader(stream, "UTF-8"), 1024000); //about 1MB. default size 8KB should not enough.
                        BufferedReader r = new BufferedReader(new InputStreamReader(stream, "UTF-8"), 4096000); //about 4MB. default size 8KB should not enough.
                        total = new StringBuilder();

                        while ((line = r.readLine()) != null) {
                            total.append(line + "\n");
                            //Log.d(TAG,line); //show xml file line by line.
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    if(sXmlSpec.loadXml(total.toString())) { //로드된 xml파일이 들어가야만 함.
                        // begin CJH 2023-05-30 : 다운로드한 스펙 파일 merge하면서 exception 발생한 경우
                        //                        파일 삭제 후 이전 스펙으로 동작하도록 예외 처리 추가
                        try {
                            mergeXmlSpecToJsonSpec();
                        } catch (Exception e) {
                            e.printStackTrace();

                            // remove parse failed file
                            File file_to_be_erased = new File(path);
                            if (file_to_be_erased.exists()) {
                                file_to_be_erased.delete();
                            }
                            sJsonSpec = null;
                            createJsonSpec(mContext);
                            return;
                        }
                        // end CJH 2023-05-30

                        Log.e(TAG,"spec successfully load!");
                        mSpecFileDownloaded = true;
                        mSpecFileLoaded = false;
                        if(mBroadcastManager != null) {
                            mBroadcastManager.sendBroadcast(new Intent(PhoneInfo.ACTION_XCP_ENGINE_SPEC_LOADED));
                        }

                        //sdcard/specification/specification_new.xml
                    } else {
                        // remove parse failed file
                        File file_to_be_erased = new File(path);
                        if (file_to_be_erased.exists()) {
                            file_to_be_erased.delete();
                        }
                    }
                }
            // begin kyeongilhan 2021-06-30 : 스펙 다운로드 실패 시 (FTP 오류) 이전 스펙 로드하도록 추가
            } else {
                createJsonSpec(mContext);
            }
            // end kyeongilhan 2021-06-30

            // begin CJH 2022-03-14 : 스펙 파일 다운로드 완료 후 버전 비교 결과로 응답하도록 수정
            /*if(command.equals(Xcp.CMD__CTRL_REQ)) {
                if(result) {
                    XcpMessage message = XcpClientSession.newRequest(Xcp.CMD__CTRL_RSP, Xcp.TARGET__UPGRADE);
                    message.setBodyValue("unit", "spec");
                    sendMessage(message);
                }
                else {
                    XcpMessage message = XcpClientSession.newRequest(Xcp.CMD__CTRL_RSP, Xcp.TARGET__UPGRADE);
                    message.setBodyValue("unit", "spec");
                    message.setBodyValue("err", "0001&FailedToUpgrade");
                    sendMessage(message);
                }
            }*/
            // end CJH 2022-03-14

            /*if (result && mSpecFileDownloaded && mSpecFileLoaded) {
                //20210105 부팅 시 스펙 파일 다운로드 완료 후 월패드 재시작하기
                Log.d(TAG, "specification initial load complete.. reboot device..");
                new Handler(Looper.getMainLooper()).post(() -> {
                    S00_21__mmg_dlg popup = new S00_21__mmg_dlg(getActivity());
                    popup.setText(R.string.s00_system_configuration_changed);
                    popup.setButtons(getResources().getString(R.string.s00__ok));
                    S00_20__dlg.showDlg(getContext(), popup);
                    S00_app.rebootDevice();
                });
            }*/
        }
    }

    private Boolean downloadAndSaveSpecification(final String userdata,
                                                 final String server,
                                                 final int portNumber,
                                                 final String user,
                                                 final String password,
                                                 final String filename,
                                                 final String localFile,
                                                 final String oldVersion,
                                                 final String getVersion) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                boolean success = false;
                /**
                 * 기본(이전) 스펙 파일 경로 : .../specification/specification.xml
                 * 다운로드 스펙 파일 경로 : .../specification/specification_new.xml
                 */
                String originFilePath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/specification/specification.xml";
                String newFilePath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/specification/";
                String error = "";
                File file = new File(newFilePath);
                file.mkdir();
                newFilePath += localFile;

                if (OliviaPref.isEnableTLS()) {
                    // begin kyeongilhan 2022-07-14 : FTPS로 변경
                    ConnectFtps ftpClient = new ConnectFtps(userdata, 10000, XcpEngine.this::specificationDownloaded, null, null);
                    if(ftpClient.ftpConnect(server, portNumber, user, password)) {
                        ftpClient.ftpDownloadFile(filename, newFilePath, 5000);
                        ftpClient.ftpDisconnect();
                        //if success, then let system know about specification path.
                        //OliviaPref.getInstance().put(OliviaPref.ADMIN__SPECIFICATION_PATH, newFilePath); //sdcard/specification/specification_new.xml

                        File downFile = new File(newFilePath);

                        if(downFile.exists() && downFile.length() > 0) {
                            if (sXmlSpec.m_version.equals(getVersion)) {
                                success = true;
                                Log.e(TAG, "spec file download and load complete! = " + downFile.getAbsolutePath() + "[" + downFile.length() + "]");
                                Log.e(TAG, "spec file server version = " + sXmlSpec.m_version + " , download version [" + getVersion + "]");
                                //Log.e(TAG, "put spec preference = " + OliviaPref.getInstance().get(OliviaPref.ADMIN__SPECIFICATION_PATH, ""));

                                // begin CJH 2023-05-30 : 다운로드 받은 스펙 파일이 정상인 경우 기존 specification.xml로 덮어쓰기한다.
                                try {
                                    if()
                                    Log.d(TAG, "renameTo = " + downFile.renameTo(new File(originFilePath)));
                                } catch (NullPointerException e) {
                                    e.printStackTrace();
                                }
                                Log.d(TAG, "renameTo = " + downFile.getAbsolutePath());
                                OliviaPref.getInstance().put(OliviaPref.ADMIN__SPECIFICATION_PATH, originFilePath);
                                Log.e(TAG, "spec preference = " + OliviaPref.getInstance().getAsciiString(OliviaPref.ADMIN__SPECIFICATION_PATH, ""));
                                // end CJH 2023-05-30

                                //20210201 스펙파일 버전 안맞으면 재시작 하지 말기기
                                //20210105 부팅 시 스펙 파일 다운로드 완료 후 월패드 재시작하기
                                Log.e(TAG, "specification load complete.. reboot device..");
                                new Handler(Looper.getMainLooper()).post(new Runnable() {
                                    @Override
                                    public void run() {
                                        // 220714 CJH reboot 화면 변경
                                        S00_23__mmg_exp_dlg.showDlg(getActivity(), R.string.s10__Update_check, R.string.s00_system_configuration_changed)
                                                .setTextCenter()
                                                .setLineColorNote();
                                        S00_app.rebootDevice(5000);
                                    }
                                });
                            } else if (sXmlSpec.m_version.equals(oldVersion)) {
                                Log.d(TAG,"Same old version specification downloaded!!");
                                // 업데이트 실패 (다운로드 실패)
                                error = Xcp.ERR__UPDATE_DOWNGRADE;
                                // CJH 2023-05-30 : 다운로드 받은 스펙 파일이 버전 mismatch인 경우 이전 스펙으로 적용
                                sJsonSpec = null;
                                createJsonSpec(mContext);
                            } else {
                                Log.d(TAG,"Wrong specification downloaded!!");
                                // 업데이트 실패 (다운로드 실패)
                                error = Xcp.ERR__UPDATE_DOWNGRADE;
                                // CJH 2023-05-30 : 다운로드 받은 스펙 파일이 버전 mismatch인 경우 이전 스펙으로 적용
                                sJsonSpec = null;
                                createJsonSpec(mContext);
                            }


                        } else {
                            // 업데이트 실패 (다운로드 실패)
                            error = Xcp.ERR__UPDATE_DOWNLOAD_FAIL;
                        /*// download failed.
                        specificationDownloaded(false, userdata, filename);
                        //if fail, then let system know there is no latest specification.
                        OliviaPref.getInstance().put(OliviaPref.ADMIN__SPECIFICATION_PATH, "");
                        OliviaPref.getInstance().put(OliviaPref.ADMIN__APT_TYPE, "A");*/
                        }
                    }
                    else {
                        // 업데이트 실패 (로그인 실패)
                        error = Xcp.ERR__UPDATE_NOT_FTP_LOGIN;
                    /*// connection failed.
                    specificationDownloaded(false, userdata, filename);
                    //if fail, then let system know there is no latest specification.
                    OliviaPref.getInstance().put(OliviaPref.ADMIN__SPECIFICATION_PATH, "");
                    OliviaPref.getInstance().put(OliviaPref.ADMIN__APT_TYPE, "A");*/
                    }
                    // 220809 CJH 스펙이 정상적으로 다운로드가 된 경우 5초 뒤 reboot을 실시하기에
                    //            ha 업데이트가 진행되지 않게 제외.
                    if(error.length() > 0) {
                        PhoneInfo.mPhoneIsUpdating = false;
                        // CJH 2023-05-30 : 다운로드 받은 스펙 파일이 버전 mismatch인 경우 파일 삭제
                        // remove parse failed file
                        File file_to_be_erased = new File(newFilePath);
                        if (file_to_be_erased.exists()) {
                            file_to_be_erased.delete();
                        }
                    }
                    // begin CJH 2022-03-14 : "unit=spec" 응답 추가
                    if (!userdata.isEmpty()) {
                        sendSpecUpdateResponse(userdata, error);
                    }
                    // end CJH 2022-03-14
                } else {
                    ConnectFtp ftpClient = new ConnectFtp(userdata, 10000, XcpEngine.this::specificationDownloaded, null);
                    if(ftpClient.ftpConnect(server, portNumber, user, password)) {
                        ftpClient.ftpDownloadFile(filename, newFilePath, 5000);
                        ftpClient.ftpDisconnect();
                        //if success, then let system know about specification path.
                        //OliviaPref.getInstance().put(OliviaPref.ADMIN__SPECIFICATION_PATH, newFilePath); //sdcard/specification/specification_new.xml

                        File downFile = new File(newFilePath);

                        if(downFile.exists() && downFile.length() > 0) {
                            if (sXmlSpec.m_version.equals(getVersion)) {
                                success = true;
                                Log.e(TAG, "spec file download and load complete! = " + downFile.getAbsolutePath() + "[" + downFile.length() + "]");
                                Log.e(TAG, "spec file server version = " + sXmlSpec.m_version + " , download version [" + getVersion + "]");
                                //Log.e(TAG, "put spec preference = " + OliviaPref.getInstance().get(OliviaPref.ADMIN__SPECIFICATION_PATH, ""));

                                //20210201 스펙파일 버전 안맞으면 재시작 하지 말기기
                                //20210105 부팅 시 스펙 파일 다운로드 완료 후 월패드 재시작하기

                                // begin CJH 2023-05-30 : 다운로드 받은 스펙 파일이 정상인 경우 기존 specification.xml로 덮어쓰기한다.
                                Log.d(TAG, "renameTo = " + downFile.renameTo(new File(originFilePath)));
                                OliviaPref.getInstance().put(OliviaPref.ADMIN__SPECIFICATION_PATH, originFilePath);
                                Log.e(TAG, "spec preference = " + OliviaPref.getInstance().getAsciiString(OliviaPref.ADMIN__SPECIFICATION_PATH, ""));
                                // end CJH 2023-05-30

                                Log.e(TAG, "specification load complete.. reboot device..");
                                new Handler(Looper.getMainLooper()).post(new Runnable() {
                                    @Override
                                    public void run() {
                                        // 220714 CJH reboot 화면 변경
                                        S00_23__mmg_exp_dlg.showDlg(getActivity(), R.string.s10__Update_check, R.string.s00_system_configuration_changed)
                                                .setTextCenter()
                                                .setLineColorNote();
                                        S00_app.rebootDevice(5000);
                                    }
                                });
                            } else if (sXmlSpec.m_version.equals(oldVersion)) {
                                Log.d(TAG,"Same old version specification downloaded!!");
                                // 업데이트 실패 (다운로드 실패)
                                error = Xcp.ERR__UPDATE_DOWNGRADE;
                                // CJH 2023-05-30 : 다운로드 받은 스펙 파일이 버전 mismatch인 경우 이전 스펙으로 적용
                                sJsonSpec = null;
                                createJsonSpec(mContext);
                            } else {
                                Log.d(TAG,"Wrong specification downloaded!!");
                                // 업데이트 실패 (다운로드 실패)
                                error = Xcp.ERR__UPDATE_DOWNGRADE;
                                // CJH 2023-05-30 : 다운로드 받은 스펙 파일이 버전 mismatch인 경우 이전 스펙으로 적용
                                sJsonSpec = null;
                                createJsonSpec(mContext);
                            }


                        } else {
                            // 업데이트 실패 (다운로드 실패)
                            error = Xcp.ERR__UPDATE_DOWNLOAD_FAIL;
                        /*// download failed.
                        specificationDownloaded(false, userdata, filename);
                        //if fail, then let system know there is no latest specification.
                        OliviaPref.getInstance().put(OliviaPref.ADMIN__SPECIFICATION_PATH, "");
                        OliviaPref.getInstance().put(OliviaPref.ADMIN__APT_TYPE, "A");*/
                        }
                    }
                    else {
                        // 업데이트 실패 (로그인 실패)
                        error = Xcp.ERR__UPDATE_NOT_FTP_LOGIN;
                    /*// connection failed.
                    specificationDownloaded(false, userdata, filename);
                    //if fail, then let system know there is no latest specification.
                    OliviaPref.getInstance().put(OliviaPref.ADMIN__SPECIFICATION_PATH, "");
                    OliviaPref.getInstance().put(OliviaPref.ADMIN__APT_TYPE, "A");*/
                    }
                    // 220809 CJH 스펙이 정상적으로 다운로드가 된 경우 5초 뒤 reboot을 실시하기에
                    //            ha 업데이트가 진행되지 않게 제외.
                    if(error.length() > 0) {
                        PhoneInfo.mPhoneIsUpdating = false;
                        // CJH 2023-05-30 : 다운로드 받은 스펙 파일이 버전 mismatch인 경우 파일 삭제
                        // remove parse failed file
                        File file_to_be_erased = new File(newFilePath);
                        if (file_to_be_erased.exists()) {
                            file_to_be_erased.delete();
                        }
                    }
                    // begin CJH 2022-03-14 : "unit=spec" 응답 추가
                    if (!userdata.isEmpty()) {
                        sendSpecUpdateResponse(userdata, error);
                    }
                    // end CJH 2022-03-14
                }


            }
        }).start();

        return true;
    }

    private static boolean mergeXmlSpecToJsonSpec() {

        if(sXmlSpec != null && sJsonSpec != null) {

            synchronized (sJsonSpec) {
                if(DEBUG_SPEC) {
                    Log.d(TAG, "/////////////////////////////////////////////////////////////////");
                    Log.d(TAG, "// NOW IT'S TIME TO TRANSFORM THIS TO JSON SPEC (DEVSPEC)");
                    Log.d(TAG, "/////////////////////////////////////////////////////////////////");
                }

                HaSpec.GlobalDevAtomicItemMap.clear();
                HaSpec.GlobalRoomAtomicItemMap.clear();

                // light
                XcpSpec.DevArray light_array = sXmlSpec.getDevArrayByPayloadValue("light");
                if(DEBUG_SPEC) Log.d(TAG, "----------- LIGHT -------------");
                HaSpec.DevItemMap light_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_tta_light);
                HaSpec.DevItemMap batch_brk_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_tta_batchbrk);
                HaSpec.DevItemMap sid_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_tta_sid);

                if(batch_brk_map != null) batch_brk_map.clear();
                if(sid_map != null) sid_map.clear();
                if(light_map != null) light_map.clear();

                if (light_array != null) {

                    for (XcpSpec.DevItem item : light_array.getDevItemList()) {
                        if (!item.use.equals("true")) continue;
                        if(DEBUG_SPEC) Log.d(TAG, item.toString());
                        try {
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_tta_batchbrk) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);

                                //20201221 batch option 추가
                                HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                slot.names.add(0, item.name);
                                slot.names.add(1, item.name_eng);
                                slot.opt.add(0, item.option);

                                jsonItem.slot.add(slot);

                                Log.d(TAG, "Alllight option = " + item.option);

                                batch_brk_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            } else if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_tta_sid) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);

                                //20201221 batch option 추가
                                HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                slot.names.add(0, item.name);
                                slot.names.add(1, item.name_eng);
                                slot.opt.add(0, item.option);

                                jsonItem.slot.add(slot);

                                Log.d(TAG, "sid option = " + item.option);

                                sid_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            } else if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_tta_light) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);
                                if (item.light_sub_list != null && item.light_sub_list.size() > 0) {
                                    for (XcpSpec.DevItem subItem : item.light_sub_list) {
                                        if (!subItem.use.equals("true")) continue;
                                        HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                        slot.names.add(0, subItem.name);
                                        slot.names.add(1, subItem.name_eng);
                                        // subItem option 은 없다.. parent item 의 옵션을 따른다.
                                        if (subItem.option != null && subItem.option.equals("2"))
                                            slot.opt.add(0, "dimming");
                                        else if (subItem.option != null && subItem.option.equals("3"))
                                            slot.opt.add(0, "special");
                                        else
                                            slot.opt.add(0, "onoff");
                                        jsonItem.slot.add(slot);
                                    }
                                } else {
                                    // 하나 밖에 없으므로 parent item 과 동일 (무조건 추가)
                                    HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                    slot.names.add(0, item.name);
                                    slot.names.add(1, item.name_eng);
                                    if (item.option != null && item.option.equals("2"))
                                        slot.opt.add(0, "dimming");
                                    else if (item.option != null && item.option.equals("3"))
                                        slot.opt.add(0, "special");
                                    else
                                        slot.opt.add(0, "onoff");
                                    jsonItem.slot.add(slot);
                                }
                                light_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }

                createAtomicDeviceItem(HaGlobal.DEV_KEY_tta_xi_batchbrk,
                        HaGlobal.DEV_ID_tta_batchbrk, batch_brk_map);
                createAtomicDeviceItem(HaGlobal.DEV_KEY_tta_xi_sid,
                        HaGlobal.DEV_ID_tta_sid, sid_map);
                createAtomicDeviceItem(HaGlobal.DEV_KEY_tta_xi_light,
                        HaGlobal.DEV_ID_tta_light, light_map);

                // gas
                XcpSpec.DevArray gas_array = sXmlSpec.getDevArrayByPayloadValue("gas");
                HaSpec.DevItemMap gas_valve_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_tta_gas);
                if(gas_valve_map != null) gas_valve_map.clear();

                if (gas_array != null) {
                    if(DEBUG_SPEC) Log.d(TAG, "----------- GAS -------------");
                    for (XcpSpec.DevItem item : gas_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_tta_gas) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);
                                gas_valve_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                createAtomicDeviceItem(HaGlobal.DEV_KEY_tta_gas,
                        HaGlobal.DEV_ID_tta_gas, gas_valve_map);

                // temp
                XcpSpec.DevArray temp_array = sXmlSpec.getDevArrayByPayloadValue("temp");
                HaSpec.DevItemMap thermostat_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_tta_thermostat);
                if(thermostat_map != null) thermostat_map.clear();

                if (temp_array != null) {
                    if(DEBUG_SPEC) Log.d(TAG, "----------- TEMP -------------");
                    int sub_index = 1;
                    List<Integer> subIdList = new ArrayList<>();
                    for (XcpSpec.DevItem item : temp_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_tta_thermostat) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);
                                int sub_id = Integer.parseInt(item.sub_id, 16);
                                // 0x1F 가 sub id 일 경우 요청은 0x11 ~ 0x19로 증가한다.
                                // 그리고 0x2F 가 오면 0x21 ~ 0x29 로 증가해야 한다.
                                // 그래서 subId 를 리스트에 저장하고 리스트에 없으면 index 를 1 로 리셋해야 한다.
                                if (!subIdList.contains(sub_id)) {
                                    subIdList.add(sub_id);
                                    sub_index = 1;
                                }

                                if ((sub_id & 0x0f) == 0x0f) { // if sub_id ends with 0x0f
                                    sub_id = (sub_id & 0xf0) | sub_index;
                                }
                                thermostat_map.put(sub_id, jsonItem);
                                sub_index++;
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                createAtomicDeviceItem(HaGlobal.DEV_KEY_tta_xi_thermostat,
                        HaGlobal.DEV_ID_tta_thermostat, thermostat_map);

                // stdbypwr
                boolean stdbypwr_tta = true;
                XcpSpec.DevArray stdbypwr_array = sXmlSpec.getDevArrayByPayloadValue("stdbypwr");
                HaSpec.DevItemMap stdbypwr_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_tta_stbypwrbrk);
                HaSpec.DevItemMap xi_stdbypwr_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_xi_stbypwrbrk);
                if(stdbypwr_map != null) stdbypwr_map.clear();
                if(xi_stdbypwr_map != null) xi_stdbypwr_map.clear();

                if (stdbypwr_array != null) {
                    if(DEBUG_SPEC) Log.d(TAG, "----------- STAND_BY_POWER -------------");
                    for (XcpSpec.DevItem item : stdbypwr_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_tta_stbypwrbrk) {
                                stdbypwr_tta = true;
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);

                                // 210511 CJH 대기전력 option 파싱 추가
                                HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                slot.names.add(0, "1번");
                                slot.names.add(1, "No.1");
                                slot.opt.add(0, TextUtils.isEmpty(item.option) ? "1" : item.option); // default 1
                                jsonItem.slot.add(slot);

                                Log.d(TAG, "STAND_BY_POWER slot.names = " + slot.names);
                                Log.d(TAG, "STAND_BY_POWER slot.opt = " + slot.opt);

                                stdbypwr_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);

                                /*try {
                                    int count = TextUtils.isEmpty(item.option) ? 1 : Integer.parseInt(item.option, 16);
                                    for (int i = 0; i < count; i++) {
                                        HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                        slot.names.add(0, String.format(Locale.getDefault(), "%d번", i + 1));
                                        slot.names.add(1, String.format(Locale.getDefault(), "No.%d", i + 1));
                                        jsonItem.slot.add(slot);
                                    }
                                } catch (NumberFormatException e) {
                                    Log.e(TAG, e.getMessage());
                                    // Option 을 parsing 할 수 없어 Error 가 나서 할 수 없을 경우에도 하나를 만든다.
                                    HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                    slot.names.add(0, "1번");
                                    slot.names.add(1, "No.1");
                                    jsonItem.slot.add(slot);
                                }*/
                            } else if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_xi_stbypwrbrk) {
                                stdbypwr_tta = false;
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);
                                xi_stdbypwr_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                                try {
                                    int count = Integer.parseInt("option", 16);
                                    for (int i = 0; i < count; i++) {
                                        HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                        slot.names.add(0, String.format(Locale.getDefault(), "%d번", i + 1));
                                        slot.names.add(1, String.format(Locale.getDefault(), "No.%d", i + 1));
                                        jsonItem.slot.add(slot);
                                    }
                                } catch (NumberFormatException e) {
                                    Log.e(TAG, e.getMessage());
                                    // Option 을 parsing 할 수 없어 Error 가 났을 경우에도 하나를 만들어야 한다.
                                    HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                    slot.names.add(0, "1번");
                                    slot.names.add(1, "No.1");
                                    jsonItem.slot.add(slot);
                                }
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                createAtomicDeviceItem(HaGlobal.DEV_KEY_tta_xi_stbypwrbrk,
                        HaGlobal.DEV_ID_tta_stbypwrbrk, stdbypwr_map);
                createAtomicDeviceItem(HaGlobal.DEV_KEY_xi_stbypwrbrk,
                        HaGlobal.DEV_ID_xi_stbypwrbrk, xi_stdbypwr_map);

                // curtain
                XcpSpec.DevArray curtain_array = sXmlSpec.getDevArrayByPayloadValue("curtain");
                HaSpec.DevItemMap curtain_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_ksx_curtain);
                if(curtain_map != null) curtain_map.clear();
                if (curtain_array != null) {
                    try {
                        if(DEBUG_SPEC) Log.d(TAG, "----------- CURTAIN -------------");
                        for (XcpSpec.DevItem item : curtain_array.getDevItemList()) {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_ksx_curtain) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);
                                curtain_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        }
                    } catch (Exception e) {
                        Log.e(TAG, e.getMessage());
                    }
                }
                createAtomicDeviceItem(HaGlobal.DEV_KEY_ksx_curtain,
                        HaGlobal.DEV_ID_ksx_curtain, curtain_map);

                // ventilator
                XcpSpec.DevArray vent_array = sXmlSpec.getDevArrayByPayloadValue("vent");
                HaSpec.DevItemMap ventilator_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_tta_ventilator);
                if(ventilator_map != null) ventilator_map.clear();
                if (vent_array != null) {
                    if(DEBUG_SPEC) Log.d(TAG, "----------- VENTILATOR -------------");
                    for (XcpSpec.DevItem item : vent_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_tta_ventilator) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);

                                //20210216 환기 옵션 추가
                                HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                slot.opt.add(item.option);
                                jsonItem.slot.add(slot);

                                ventilator_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                createAtomicDeviceItem(HaGlobal.DEV_KEY_tta_xi_ventilator,
                        HaGlobal.DEV_ID_tta_ventilator, ventilator_map);

                // remote meter
                XcpSpec.DevArray meter_array = sXmlSpec.getDevArrayByPayloadValue("meter");
                HaSpec.DevItemMap meter_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_tta_meterread);
                HaSpec.DevItemMap xi_meter_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_xi_meterread);
                if(meter_map != null) meter_map.clear();
                if(xi_meter_map != null) xi_meter_map.clear();
                if (meter_array != null) {
                    HaSpec.DevItem ttaJsonMain = null;
                    if(DEBUG_SPEC) Log.d(TAG, "----------- REMOTE METER -------------");
                    for (XcpSpec.DevItem item : meter_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_tta_meterread) {
                                // TTA  type 은 하나라도 존재한다면 sub_id 는 0x0f로 지정한다.
                                // 나머지는 sub 로 지정한다.
                                if (ttaJsonMain == null) {
                                    ttaJsonMain = new HaSpec.DevItem();
                                    ttaJsonMain.names.add(0, item.name);
                                    ttaJsonMain.names.add(1, item.name_eng);
                                    meter_map.put(0x0F, ttaJsonMain);
                                }
                                // sub id 가 에너지 타입을 정의 하지만 실제로는 필요가 없다.
                                // 485 기기 에서 정보가 오기 때문이고 GUI 에서는 이 정보를 보고 에너지 타입을 결정한다.
                                // 하지만 만약의 경우를 대비해서 여기에 정의한다.
                                // option 은 에너지 타입에 대한 단위를 지정한다.
                                HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                slot.names.add(0, item.name);
                                slot.names.add(1, item.name_eng);
                                slot.opt.add(item.option);
                                ttaJsonMain.slot.add(slot);
                            } else if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_xi_meterread) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);
                                xi_meter_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }

                createAtomicDeviceItem(HaGlobal.DEV_KEY_tta_xi_meterread,
                        HaGlobal.DEV_ID_tta_meterread, meter_map);

                createAtomicDeviceItem(HaGlobal.DEV_KEY_xi_meterread,
                        HaGlobal.DEV_ID_xi_meterread, xi_meter_map);

                // subphone
                XcpSpec.DevArray subphone_array = sXmlSpec.getDevArrayByPayloadValue("subphone");
                HaSpec.DevItemMap subphone_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_xi_subphone);
                if (subphone_array != null) {
                    subphone_map.clear();
                    if(DEBUG_SPEC) Log.d(TAG, "----------- SUBPHONE -------------");
                    for (XcpSpec.DevItem item : subphone_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_xi_subphone) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);

                                // begin kyeongilhan 2023-01-17 : subphone 옵션 추가 (pstn 지원)
                                HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                slot.opt.add(item.option);
                                jsonItem.slot.add(slot);

                                subphone_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                createAtomicDeviceItem(HaGlobal.DEV_KEY_xi_subphone,
                        HaGlobal.DEV_ID_xi_subphone, subphone_map);

                // doorlock
                XcpSpec.DevArray doorlock_array = sXmlSpec.getDevArrayByPayloadValue("doorlock");
                HaSpec.DevItemMap doorlock_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_tta_doorlock);
                if(doorlock_map != null) doorlock_map.clear();
                if (doorlock_array != null) {
                    doorlock_map.clear();
                    if(DEBUG_SPEC) Log.d(TAG, "----------- DOOR LOCK -------------");
                    for (XcpSpec.DevItem item : doorlock_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_xi_subphone) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);
                                doorlock_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }

                createAtomicDeviceItem(HaGlobal.DEV_KEY_tta_xi_doorlock,
                        HaGlobal.DEV_ID_xi_subphone, doorlock_map);

                // xi_tems
                XcpSpec.DevArray xi_tems_array = sXmlSpec.getDevArrayByPayloadValue("xi_tems");
                HaSpec.DevItemMap xi_tems_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_xi_tems);
                if(xi_tems_map != null) xi_tems_map.clear();
                if (xi_tems_array != null) {
                    if(DEBUG_SPEC) Log.d(TAG, "----------- XI TEMS -------------");
                    for (XcpSpec.DevItem item : xi_tems_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_xi_tems) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);
                                xi_tems_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                createAtomicDeviceItem(HaGlobal.DEV_KEY_xi_tems,
                        HaGlobal.DEV_ID_xi_tems, xi_tems_map);

                // Sysclein
                XcpSpec.DevArray sysclein_array = sXmlSpec.getDevArrayByPayloadValue("fau"); //fau 표기는 시스클라인임.
                HaSpec.DevItemMap sysclein_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_xi_sysclein);
                if(sysclein_map != null) sysclein_map.clear();

                if (sysclein_array != null) {
                    if(DEBUG_SPEC) Log.d(TAG, "----------- SYSCLEIN -------------");
                    for (XcpSpec.DevItem item : sysclein_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_xi_sysclein) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);

                                //20210315 시스클라인 옵션 추가 (1이면 한성, 신동은 없음)
                                //20210322 삭제 -> iconlist의 옵션에서 가져오도록
                                /*HaSpec.DoubleList slot = new HaSpec.DoubleList();
                                if (item.option != null) {
                                    if (!item.option.equals("")) {
                                        slot.opt.add(item.option);
                                        jsonItem.slot.add(slot);
                                    }
                                }*/

                                sysclein_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                createAtomicDeviceItem(HaGlobal.DEV_KEY_xi_sysclein,
                        HaGlobal.DEV_ID_xi_sysclein, sysclein_map);

                // AIR CONDITIONER
                XcpSpec.DevArray aircon_array = sXmlSpec.getDevArrayByPayloadValue("aircon"); //표기 미정.
                HaSpec.DevItemMap aircon_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_lg_aircon);
                if(aircon_map != null) aircon_map.clear();

                if (aircon_array != null) {
                    if(DEBUG_SPEC) Log.d(TAG, "----------- AIR CONDITIONER -------------");
                    for (XcpSpec.DevItem item : aircon_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_lg_aircon) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);
                                aircon_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                createAtomicDeviceItem(HaGlobal.DEV_KEY_lg_aircon,
                        HaGlobal.DEV_ID_lg_aircon, aircon_map);

                // airconditioner
                /*XcpSpec.DevArray aircondition_array = sXmlSpec.getDevArrayByPayloadValue("aircondition");
                HaSpec.DevItemMap aircondition_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_lg_aircon);
                if(aircondition_map != null) aircondition_map.clear();

                if (aircondition_array != null) {
                    if(DEBUG_SPEC) Log.d(TAG, "----------- GAS -------------");
                    for (XcpSpec.DevItem item : aircondition_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_lg_aircon) {
                                HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                jsonItem.names.add(0, item.name);
                                jsonItem.names.add(1, item.name_eng);
                                gas_valve_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                createAtomicDeviceItem(HaGlobal.DEV_KEY_aircondition,
                        HaGlobal.DEV_ID_aircondition, aircondition_map);*/

                // energy
                XcpSpec.DevArray energy_array = sXmlSpec.getDevArrayByPayloadValue("energy");
                HaSpec.EnergyItemMap energy_map = sJsonSpec.getEnergyMap();
                if(energy_map != null) energy_map.clear();
                if (energy_array != null) {
                    int index = 0;
                    if(DEBUG_SPEC) Log.d(TAG, "----------- ENERGY -------------");
                    for (XcpSpec.DevItem item : energy_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            HaSpec.EnergyItem jsonItem = new HaSpec.EnergyItem();
                            jsonItem.names.add(0, item.name);
                            jsonItem.names.add(1, item.name_eng);
                            //20210202 에너지 표시 단위 텍스트 수정
                            if ((item.name_eng != null) && (item.name_eng.equals("Water") || item.name_eng.equals("Gas"))) {
                                jsonItem.unit = "㎥";
                            } else {
                                jsonItem.unit = item.option;
                            }
                            energy_map.put(++index, jsonItem);
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }

                // interphone
                XcpSpec.DevArray interphone_array = sXmlSpec.getDevArrayByPayloadValue("interphone");
                HaSpec.InterphoneItemMap interphone_map = sJsonSpec.getInterphoneMap();
                if(interphone_map != null) interphone_map.clear();
                if (interphone_array != null) {
                    interphone_map.clear();
                    if(DEBUG_SPEC) Log.d(TAG, "----------- INTERPHONE -------------");
                    int index = 0;
                    for (XcpSpec.DevItem item : interphone_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            HaSpec.InterphoneItem jsonItem = new HaSpec.InterphoneItem();
                            jsonItem.names.add(0, item.name);
                            jsonItem.names.add(1, item.name_eng);
                            jsonItem.address = item.option;
                            interphone_map.put(++index, jsonItem);
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                // cctv
                XcpSpec.DevArray cctv_array = sXmlSpec.getDevArrayByPayloadValue("cctv");
                HaSpec.CctvItemMap cctv_map = sJsonSpec.getCctvMap();
                if(cctv_map != null) cctv_map.clear();
                if (cctv_array != null) {
                    cctv_map.clear();
                    if(DEBUG_SPEC) Log.d(TAG, "----------- CCTV -------------");
                    int index = 0;
                    for (XcpSpec.DevItem item : cctv_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            HaSpec.CctvItem jsonItem = new HaSpec.CctvItem();
                            jsonItem.names.add(0, item.name);
                            jsonItem.names.add(1, item.name_eng);
                            String[] info = item.option.split(",");
                            if (info.length == 5) {
                                if (info[0].startsWith("rtsp://")) {
                                    try {
                                        String protocol = "rtsp";
                                        String host = info[0].replace("rtsp://", "");
                                        int port = Integer.parseInt(info[1]);
                                        String auth = info[2] + ":" + info[3];
                                        String path = info[4];
                                        URI uri = new URI(protocol, auth, host, port, path, null, null);
                                        if (DEBUG_SPEC)
                                            Log.d(TAG, "cctv address = " + uri.toString());
                                        jsonItem.address = uri.toString();
                                        jsonItem.port = "";
                                        jsonItem.user = "";
                                        jsonItem.pwd = "";
                                        jsonItem.index = "0";
                                        cctv_map.put(++index, jsonItem);
                                    } catch (Exception e) {
                                        Log.e(TAG, e.getMessage());
                                    }
                                }
                                else {
                                    jsonItem.address = info[0];
                                    jsonItem.port = info[1];
                                    jsonItem.user = info[2];
                                    jsonItem.pwd = info[3];
                                    jsonItem.index = info[4];
                                    if (DEBUG_SPEC) {
                                        Log.d(TAG, "cctv address = " + jsonItem.address
                                                + "," + jsonItem.port + "," + jsonItem.user + "," + jsonItem.pwd + "," + jsonItem.index);
                                    }
                                    cctv_map.put(++index, jsonItem);
                                }
                            }
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                // elevator
                XcpSpec.DevArray elevator_array = sXmlSpec.getDevArrayByPayloadValue("elevator");
                HaSpec.ElevatorItemMap elevator_map = sJsonSpec.getElevatorMap();
                if(elevator_map != null) elevator_map.clear();
                if (elevator_array != null) {
                    elevator_map.clear();
                    if(DEBUG_SPEC) Log.d(TAG, "----------- ELEVATOR -------------");
                    int index = 0;
                    for (XcpSpec.DevItem item : elevator_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            HaSpec.ElevatorItem jsonItem = new HaSpec.ElevatorItem();
                            jsonItem.names.add(0, item.name);
                            jsonItem.names.add(1, item.name_eng);
                            elevator_map.put(++index, jsonItem);
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }
                }
                // reset
                XcpSpec.DevArray reset_array = sXmlSpec.getDevArrayByPayloadValue("reset");
                if (reset_array != null) {
                    if(DEBUG_SPEC) {
                        Log.d(TAG, "----------- RESET -------------");
                        for (XcpSpec.DevItem item : reset_array.getDevItemList()) {
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                        }
                    }
                }
                // booting_update
                XcpSpec.DevArray booting_array = sXmlSpec.getDevArrayByPayloadValue("booting_update");
                if (booting_array != null) {
                    if(DEBUG_SPEC) {
                        Log.d(TAG, "----------- BOOTING -------------");
                        for (XcpSpec.DevItem item : booting_array.getDevItemList()) {
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                        }
                    }
                }
                // site_type
                HaSpec.SiteTypeMap siteTypeMap = new HaSpec.SiteTypeMap();
                XcpSpec.DevArray site_type_array = sXmlSpec.getDevArrayByPayloadValue("site_type");
                if (site_type_array != null) {
                    if(DEBUG_SPEC) {
                        Log.d(TAG, "----------- SITE TYPE -------------");
                        for (XcpSpec.DevItem item : site_type_array.getDevItemList()) {
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            HaSpec.SiteTypeItem jsonItem = new HaSpec.SiteTypeItem();
                            jsonItem.names.add(0, item.name);
                            jsonItem.names.add(1, item.name_eng);
                            int id = Integer.parseInt(item.getServerNo(), 16);

                            if (!item.option.equals("")) jsonItem.option = item.option; // try to put empty string.
                            else jsonItem.option = "";

                            jsonItem.use = item.use.equals("true");
                            siteTypeMap.put(id, jsonItem);

                            // begin CJH 2023-04-25 : AES, TLS 스펙 옵션에 따라 설정 기능 추가
                            if(id == 0x23 && jsonItem.use) {
                                // begin CJH 2023-05-30 : 옵션값이 integer인 경우에만 적용
                                boolean isInteger = jsonItem.option.matches(("-?\\d+"));
                                if(isInteger) {
                                    int option = Integer.parseInt(jsonItem.option);
                                    Log.d(TAG, "TLS opt = " + option);
                                    switch (option) {
                                        case 1: // AES
                                            if(!OliviaPref.isEnableAES()) {
                                                OliviaPref.setValue(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.AES_PORT);
                                            }
                                            break;
                                        case 2: // TLS
                                            if(!OliviaPref.isEnableTLS()) {
                                                OliviaPref.setValue(OliviaPref.ADMIN__COMPLEX_SERVER_PORT, Xcp.TLS_PORT);
                                            }
                                            break;
                                        default:
                                            break;
                                    }
                                }
                                // end CJH 2023-05-30
                            }
                            // end CJH 2023-04-25
                            // begin CJH 2022-12-05 : 최초 스펙 파일 load 시에 초기화 진행
                            else if(id == 33 && jsonItem.use) {
                                String idx = jsonItem.option.replaceAll("[^0-9]","");
                                if(!TextUtils.isEmpty(idx)) {
                                    mRemoveLivingDimming = Integer.parseInt(idx);
                                    ProxyApi.req_UPDATE_etc_rm_dimming(S00_app.getInstance().getContentResolver(), mRemoveLivingDimming);
                                }
                            }
                            // end CJH 2022-12-05
                        }
                        sJsonSpec.setSiteTypeMap(siteTypeMap);
                    }
                }
                // icon list
                XcpSpec.DevArray icon_list_array = sXmlSpec.getDevArrayByPayloadValue("iconlist");
                HaSpec.MenuItemMap menu_map = sJsonSpec.getMenu();
                if(menu_map != null) menu_map.clear();
                if (icon_list_array != null) {
                    if(DEBUG_SPEC) Log.d(TAG, "----------- ICON LIST -------------");
                    for (XcpSpec.DevItem item : icon_list_array.getDevItemList()) {
                        try {
                            if (!item.use.equals("true")) continue;
                            if(DEBUG_SPEC) Log.d(TAG, item.toString());
                            HaSpec.MenuItem jsonItem = new HaSpec.MenuItem();
                            jsonItem.names.add(0, item.name);
                            jsonItem.names.add(1, item.name_eng);
                            int id = Integer.parseInt(item.getServerNo(), 16);
                            jsonItem.option = ""; // try to put empty string.
                            if (id == APP_MENU_STANDBYPOWER) {
                                /* 대기 전력 */
//                                jsonItem.option = stdbypwr_tta ? "tta" : "xi";
                                // 210517 CJH 대기전력 iconlist option 변경 (0: TTA, WIDGET TRUE, 1: TTA, WIDGET FAlSE, 2: ezVille, WIDGET TRUE, 3: ezVille, WIDGET FAlSE)
                                jsonItem.option = item.option.equals("") ? "0" : item.option;
                                Log.d(TAG, "jsonItem.option = " + jsonItem.option);
                                // 20201215 iconlist의 option 도 스펙 객체에 반영되도록 변경
                            } else if (id == APP_MENU_GAS_VALVE) {
                                // begin CJH 2022-11-01 : 범어 자이엘라 쿡탑 연동 옵션 추가
                                //                        특성 정보가 아닌 스펙으로 UI 강제 구성
                                if(item.option.equals("2"))
                                    ProxyApi.req_UPDATE_etc_cooktop_ui(S00_app.getInstance().getContentResolver(), 1);
                                // end CJH 2022-11-01
                            } else if (!item.option.equals("")) {
                                jsonItem.option = item.option;
                            }
                            jsonItem.app = findAppNameById(id);
                            menu_map.put(id, jsonItem);
                        } catch (Exception e) {
                            Log.e(TAG, e.getMessage());
                        }
                    }

                    // begin CJH 2023-01-17 : 환경센서 추가, xml 파싱하여 map에 저장.
                    // envirsensor
                    XcpSpec.DevArray envirsensor_array = sXmlSpec.getDevArrayByPayloadValue("envirsensor");
                    HaSpec.DevItemMap envirsensor_map = sJsonSpec.getDevItemMap(HaGlobal.DEV_ID_tta_envirsensor);
                    if (envirsensor_array != null) {
                        envirsensor_map.clear();
                        if(DEBUG_SPEC) Log.d(TAG, "----------- envirsensor -------------");
                        for (XcpSpec.DevItem item : envirsensor_array.getDevItemList()) {
                            try {
                                if (!item.use.equals("true")) continue;
                                if(true) Log.d(TAG, item.toString());
                                if (Integer.parseInt(item.device_id, 16) == HaGlobal.DEV_ID_tta_envirsensor) {
                                    HaSpec.DevItem jsonItem = new HaSpec.DevItem();
                                    jsonItem.names.add(0, item.name);
                                    jsonItem.names.add(1, item.name_eng);
                                    envirsensor_map.put(Integer.parseInt(item.sub_id, 16), jsonItem);
                                }
                            } catch (Exception e) {
                                Log.e(TAG, e.getMessage());
                            }
                        }
                    }

                    createAtomicDeviceItem(HaGlobal.DEV_KEY_tta_xi_envirsensor,
                            HaGlobal.DEV_ID_tta_envirsensor, envirsensor_map);
                    // end CJH 2023-01-17
                }
            }

            ////// DEBUG ////////
            //printAtomicItemMap();
            //printRoomGrpMap();
            mSpecFileLoaded = true;
        }
        return false;
    }

    /**
     * Atomic Device Item Map 을 생성한다.
     * 해당 json 이 DevItemMap 타입이 아닐 수 있으므로
     * try / exception 구문을 넣어서 최종적으로 parsing
     * 자체가 안되도록 해야 한다.
     * @param devClass
     * @param devId
     * @param obj
     */
    private static void createAtomicDeviceItem(String devClass, int devId, Object obj) {
        // this may throw exception..
        try {
            HaSpec.DevItemMap itemMap = (HaSpec.DevItemMap) obj;
            if(itemMap!=null){
                for (Integer subId : itemMap.keySet()) {
                    int index = (devId << 8 | subId ); // example devId = 0x0e && subId = 0x12 -> index = 0x0e12
                    if(!HaSpec.GlobalDevAtomicItemMap.containsKey(index)) {
                        HaSpec.DevAtomicItem atomicItem = new HaSpec.DevAtomicItem();
                        atomicItem.deviceClass = devClass;
                        atomicItem.deviceId = devId;
                        atomicItem.subId = subId;
                        atomicItem.devItem = itemMap.get(subId);
                        HaSpec.GlobalDevAtomicItemMap.put(index, atomicItem);
                        // CJH 2023-01-17 : 환기, 환경센서 방별 제어 제외
                        if (!devClass.equals(HaGlobal.DEV_KEY_tta_xi_ventilator) && !devClass.equals(HaGlobal.DEV_KEY_tta_xi_envirsensor))
                            createItemToRoomGrp(atomicItem);

                    }
                }
            }
        }
        catch(ClassCastException e) {
            Log.e(TAG, "ClassCastException expected");
        }
    }

    /**
     * 실별 제어를 위해서 미리 Room 별로 구별해서
     * 기기를 제어하도록 한다.
     * @param item DevAtomicItem
     */
    private static void createItemToRoomGrp(HaSpec.DevAtomicItem item) {
        if(item == null) return;
        if(item.devItem == null) return;
        if(item.devItem.names == null) return;
        if(item.devItem.names.size() == 0) return;
        // 방이 이미 존재 하는 지 먼저 살펴 본다.
        int index = HaSpec.getRoomItemIndex(item.devItem.names.get(0));
        HaSpec.RoomGrpItem roomGrp = null;
        if (index < 0) {
            // 방이 존재하지 않으므로 방을 하나 만들어야 한다.
            roomGrp = new HaSpec.RoomGrpItem();
            // 방이름을 복사하고
            roomGrp.names.addAll(item.devItem.names);
            // index 를 현재 index + 1 로 늘린다.
            index = HaSpec.GlobalRoomAtomicItemMap.size();
        } else {
            // 방이 이미 존재 한다. 해당 방을 가져온다.
            roomGrp = HaSpec.GlobalRoomAtomicItemMap.get(index);
        }
        // 새로운 Device 를 추가한다.
        int deviceKey = roomGrp.devices.size();
        roomGrp.devices.put(deviceKey, item);
        // room item map 을 업데이트 한다.
        //Log.d(TAG, "adding to the room -> " + index + roomGrp.names.get(0));
        HaSpec.GlobalRoomAtomicItemMap.put(index, roomGrp);

    }

    private Boolean downloadAndSaveCertification(final String userdata,
                                                 final String server,
                                                 final int portNumber,
                                                 final String user,
                                                 final String password,
                                                 final String filename) {
        new Thread(new Runnable() {
            @Override
            public void run() {

                try {
                    String newFilePath = Environment.getExternalStorageDirectory().getAbsolutePath()+"/cert";
                    File file = new File(newFilePath);
                    file.mkdir();
                    newFilePath += "/temp.pfx";
                    ConnectFtps ftpsClient = new ConnectFtps(userdata, 10000, XcpEngine.this::tempCertificationDownloaded, null, null);

                    if(ftpsClient.ftpConnect(server, portNumber, user, password)) {
                        ftpsClient.ftpDownloadFile("/cert/temp.pfx", newFilePath, 5000);
                        ftpsClient.ftpDisconnect();

                        File downFile = new File(newFilePath);

                        if(downFile.exists() && downFile.length() > 0) {
                            XcpEngine.restartService();
                        } else {
                            // 전부 실패
                            tempCertificationDownloaded(false, null, null);
                        }
                    } else {
                        tempCertificationDownloaded(false, null, null);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    tempCertificationDownloaded(false, null, null);
                }

            }
        }).start();

        return true;
    }

    private static String findAppNameById(int id) {
        try {
            return sMenuTree.get(id);
        }
        catch(IndexOutOfBoundsException e) {
            Log.e(TAG, e.getMessage());
        }
        return "";
    }

    private static void printAtomicItemMap() {
        Log.d(TAG, "--------------------------------------------------");
        for (Integer atomicId : HaSpec.GlobalDevAtomicItemMap.keySet()) {
            HaSpec.DevAtomicItem atomicItem = HaSpec.GlobalDevAtomicItemMap.get(atomicId);
            printSingleAtomicItem(atomicItem);
        }
        Log.d(TAG, "--------------------------------------------------");
    }

    private static void printSingleAtomicItem(HaSpec.DevAtomicItem atomicItem) {
            Log.d(TAG, "device atomic item (" +
                    " & device class = " + atomicItem.deviceClass +
                    " & device id = " + atomicItem.deviceId +
                    " & sub id = " + atomicItem.subId +
                    " & room name = " + atomicItem.devItem.names.get(0) +
                    ")");
    }

    private static void printRoomGrpMap() {
        Log.d(TAG, "-------------------------------------------------- " + HaSpec.GlobalRoomAtomicItemMap.size());

        for (Integer index : HaSpec.GlobalRoomAtomicItemMap.keySet()) {
            HaSpec.RoomGrpItem roomGrp = HaSpec.GlobalRoomAtomicItemMap.get(index);
            Log.d(TAG, "Room name => [" + roomGrp.names.get(0) + ", " + roomGrp.names.get(1) + "]");
            for (HaSpec.DevAtomicItem item : roomGrp.devices.values()) {
                printSingleAtomicItem(item);
            }
        }
        Log.d(TAG, "--------------------------------------------------");
    }

    public String getMacAddress() {
        if(!PhoneInfo.isEmulator()) {
            try {
                List<NetworkInterface> all = Collections.list(NetworkInterface.getNetworkInterfaces());
                for (NetworkInterface nif : all) {

                    //Log.d(TAG, "network interface name = " + nif.getName());

                    if (!nif.getName().equalsIgnoreCase("eth0")) continue;

                    byte[] macBytes = nif.getHardwareAddress();
                    if (macBytes == null) {
                        return null;
                    }

                    //Log.d(TAG, "macBytes = " +new String(macBytes));

                    StringBuilder res1 = new StringBuilder();
                    for (byte b : macBytes) {
                        //res1.append(Integer.toHexString(b & 0xFF) + ":");
                        res1.append(String.format("%02X", b));
                        //res1.append("**:");
                    }

/*                    if (res1.length() > 0) {
                        res1.deleteCharAt(res1.length() - 1);
                    }*/
                    return res1.toString();
                }
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }
        return null;
    }

    // 20210513 NTP 추가 (TLS 일때만 동작)
    public interface SystemTimeCallback {
        void onGetSystemTime(long time);
    }

    private static int ntpRetryCount = 30;

    public void ntpProcess() {

        Handler handler = new Handler(Looper.getMainLooper());

        Log.e(TAG, "[NTP] Start NTP Process!!");
        getSystemTime(time -> {
            // 20210513 NTP 성공했을 때만 TLS한다
            if (time > 0) {
                //Log.d(TAG, "[NTP] NTP Process Success! put preference");
                setSystemTime(time);
                handler.removeCallbacksAndMessages(null);
                OliviaPref.setValue(OliviaPref.ADMIN__NTP_SUCCESS, true);
            } else {
                // 5초에 한번 재시도 해서 성공하면 통신
                // 30회 재시도 실패 시 as 받으라는 팝업을 띄운다 (이때부턴 1시간 단위로 시도)
                if (ntpRetryCount == 0) {
                    // begin kyeongilhan 2022-07-18 : ntp 팝업 삭제
                    /*S00_app.screenWakeUpWorkAround();
                    S00_21__mmg_dlg popup = new S00_21__mmg_dlg(getActivity());
                    popup.setTimeout(PtGlobal.NOTICE_NTP_POPUP_TIME);
                    popup.setText(getResources().getString(R.string.ntp_failed));
                    popup.setButtons(getResources().getString(R.string.s00__ok));
                    S00_20__dlg.showDlg(getActivity(), popup);*/

                    // 1시간 뒤 다시 시도
                    handler.postDelayed(this::ntpProcess, 60000*60);
                }

                if (ntpRetryCount > 0) {
                    handler.postDelayed(this::ntpProcess, 5000);
                    ntpRetryCount--;
                }

                Log.d(TAG, "ntp Retry count = " + ntpRetryCount);
            }
        });
    }

    public void getSystemTime(final SystemTimeCallback systemTimeCallback) {

        NtpClient ntpClient = new NtpClient(mContext, time -> {
            //Log.d("NTP", "System Time = " + time);
            systemTimeCallback.onGetSystemTime(time);
        });

        try {
            ntpClient.startNTPTask();
        } catch (IOException e) {
            e.printStackTrace();
            systemTimeCallback.onGetSystemTime(0);
        }
    }

    private void setSystemTime(long time) {
        Log.d(TAG, "NTP Success! Set System Time!");
        final Calendar c = Calendar.getInstance();
        c.setTimeInMillis(time);
        AlarmManager alarmManager = (AlarmManager) mContext.getSystemService(ALARM_SERVICE);
        alarmManager.setTime(c.getTimeInMillis());
    }

    public ConnectionType getConnectionType() {
        return mConnectionType;
    }

    // begin CJH 2022-09-05 : 피난사다리 2 추가
    /**
     * 스펙 파일 SiteType 중 "안방비상표시" 옵션 return
     * @return
     */
    public long getLadder2Detect() {
        long sensor_index = Sensor.EMERGENCY_BREAKER.getIndex();
        HaSpec.SiteTypeMap siteTypeMap = XcpEngine.createJsonSpec(S00_app.getContext()).getSiteTypeMap();
        if (siteTypeMap != null) {
            for (Map.Entry<Integer, HaSpec.SiteTypeItem> entry : siteTypeMap.entrySet()) {
                int id = entry.getKey();
                HaSpec.SiteTypeItem item = entry.getValue();
                if (id == 0x06) {
                    if (item.use) {
                        //"5"   is "피난 사다리 2번으로 사용"
                        //etc   미구현
                        if (item.option != null && item.option.length() > 0) {
                            if(item.option.equals("5")) sensor_index = Sensor.LADDER2.getIndex();
                        }
                    }
                }
            }
        }
        return sensor_index;
    }
    // end CJH 2022-09-05

	// begin kyeongilhan 2021-06-02 : 스펙의 테라스옵션체크
     public static boolean checkIsTerrace() {
        boolean isTerrace = false;

        //site_type을 가져온다
        HaSpec.SiteTypeMap siteTypeMap = XcpEngine.createJsonSpec(S00_app.getContext()).getSiteTypeMap();
        if (siteTypeMap != null) {
            for (Map.Entry<Integer, HaSpec.SiteTypeItem> entry : siteTypeMap.entrySet()) {
                int id = entry.getKey();
                HaSpec.SiteTypeItem item = entry.getValue();
                //0x03가 테라스 옵션이다
                if (id == 0x03) {
                    if (item.use) {
                        Log.d(TAG, "[Terrace] Use terrace option!!");
                        isTerrace = true;
                    }
                }
            }
        }
        return isTerrace;
    }
    // end kyeongilhan 2021-06-02

    // begin kyeongilhan 2022-06-20 : 월패드카메라사용 옵션 체크
    public static int checkWallpadCameraUse() {
        int option = 1;

        //site_type을 가져온다
        HaSpec.SiteTypeMap siteTypeMap = XcpEngine.createJsonSpec(S00_app.getContext()).getSiteTypeMap();
        if (siteTypeMap != null) {
            for (Map.Entry<Integer, HaSpec.SiteTypeItem> entry : siteTypeMap.entrySet()) {
                int id = entry.getKey();
                HaSpec.SiteTypeItem item = entry.getValue();
                if (id == 32) {
                    if (item.use) {
                        Log.d(TAG, "[WallpadCamera] parse wallpad camera option = " + item.option);
                        option = Integer.parseInt(item.option);
                    }
                }
            }
        }
        return option;
    }
    // end kyeongilhan 2022-06-20

    // 220520 CJH 안심케어 Enable
    // TDS 3.0과 동일하게 siteMap 에서 check
    public static boolean checkIsRcare() {
        boolean isRcare = false;

        HaSpec.SiteTypeMap siteTypeMap = XcpEngine.createJsonSpec(S00_app.getContext()).getSiteTypeMap();
        if (siteTypeMap != null) {
            for (Map.Entry<Integer, HaSpec.SiteTypeItem> entry : siteTypeMap.entrySet()) {
                int id = entry.getKey();
                HaSpec.SiteTypeItem item = entry.getValue();
                if (id == 0x17) {
                    if (item.use) {
                        Log.d(TAG, "Enable Rcare");
                        isRcare = true;
                    }
                }
            }
        }
        return isRcare;
    }

    /**
     * CJH 2022-07-14
     * checkNewVersion() : 업데이트 할 버전이 있는지 check
     * 단지서버로 uni=ha 메시지의 s/w 버전이 현재 버전보다 높은 경우 실시
     * 현재 버전과 동일한 경우 업데이트 완료 메시지 전달
     * etc Error return
     */
    private void checkNewVersion() {
        int result = Xcp.UPDATE_FAIL_UPGRADE;
        String updateVersion = OliviaPref.getValue(OliviaPref.ADMIN__SW_VERSION, "");
        Log.d(TAG, "checkNewVersion updateVersion = " + updateVersion);

        // 220805 CJH 강제 업데이트 기능 추가, unit="force_on" 수신 시 버전 비교하지 않고 강제 업데이트 진행
        if (!TextUtils.isEmpty(updateVersion)) {
            if(OliviaPref.getForceUpdate()) {
                // 1회 실행 후 무조건 false로 돌려준다.
                OliviaPref.setForceUpdate(false);
                UpdateCheckThread updateCheck = new UpdateCheckThread(updateVersion);
                Thread t = new Thread(updateCheck);
                t.start();
                return;
            } else {
                try {
                    Version newVersion = new Version(updateVersion);
                    Version oldVersion = new Version(BuildConfig.VERSION_NAME);

                    switch (oldVersion.compareTo(newVersion)) {
                        case 0 :
                            result = Xcp.UPDATE_SUCCESS_UPGRADE;
                            break;
                        case 1 :
                            result = Xcp.UPDATE_ERR_DOWNGRADE;
                            break;
                        case -1 :
                            // 무한 업데이트 시도 및 reboot 방지를 위해 1회 명령어 요청 시 1회만 실시
                            boolean swUpdated = OliviaPref.getValue(OliviaPref.ADMIN__LAST_SW_UPDATED, true);
                            Log.d(TAG, "checkNewVersion swUpdated = " + swUpdated);
                            if (!swUpdated) {
                                UpdateCheckThread updateCheck = new UpdateCheckThread(updateVersion);
                                Thread t = new Thread(updateCheck);
                                t.start();
                                return;
                            }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    result = Xcp.UPDATE_ERR_INVALID_VERSION;
                }
            }
            UpgradeMessage.sendUpdateResult(result);
        } else {
            // 업데이트 요쳥 이력이 없다면 단지서버로 전달하지 않는다.
        }
    }

    /**
     * CJH 2022-02-24
     * checkUpdateComplete() : rs485mst 무결성 체크 Func
     * 런처의 경우 size가 너무 커서 timeout 발생하여 제외.
     * 업데이트 시에 preference에 저장한 checksum으로 비교 후 이를 단지서버로 전달한다.
     */
    private void checkUpdateComplete() {
        class UpdateRunnable implements Runnable {
            @Override
            public void run() {
                try {
                    String hashValue = OliviaPref.getValue(OliviaPref.ADMIN__MST_CHECKSUM, "");

                    if(hashValue.length() > 0) {
                        String md5str = ZipUtils.Filemd5.filemd5("system/bin/rs485mst").toLowerCase();
                        /*if (hashValue.equals(md5str)) {
                            UpgradeMessage.sendUpdateResult();
                        } else {
                            // 코드 살려 두면 무한 업데이트 가능성이 존재.
                            // UpgradeMessage.requestHaUpgrade();
                        }*/
//                        UpgradeMessage.sendUpdateResult(hashValue.equals(md5str));
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        };

        UpdateRunnable updateRunnable = new UpdateRunnable();
        Thread t = new Thread(updateRunnable);
        t.start();
    }

    /**
     * CJH 2022-07-18
     * sendSpecUpdateResponse() : 스펙 업데이트 결과 응답 추가
     * 응답 시 copy값이 맞지 않아 스테이션에 "NG"가 출력되지 않는 문제 수정
     * station 에서는 에러 필드 유무로만 판단, 따라서 2번 보낼 필요가 없음.
     */
    public void sendSpecUpdateResponse(String copy, String errorMsg) {
        if (XcpEngine.canCommunicate()) {
            XcpMessage message = XcpClientSession.newRequest(Xcp.CMD__CTRL_RSP, Xcp.TARGET__UPGRADE);
            message.setHeaderValue(Xcp.COPY, copy);
            message.setBodyValue("unit", "spec");
            if (errorMsg.length() > 0) {
                message.setBodyValue("err", errorMsg);
//                message.setBodyValue("err", "0001&FailedToUpgrade");
            }
            XcpEngine.getInstance().sendMessage(message);
        }
    }
}


