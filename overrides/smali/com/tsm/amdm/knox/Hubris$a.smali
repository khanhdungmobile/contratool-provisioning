.class Lcom/tsm/amdm/knox/Hubris$a;
.super Ljava/lang/Object;
.source "LGATCMDClient.java"

# interfaces
.implements Landroid/content/ServiceConnection;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/tsm/amdm/knox/Hubris;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/tsm/amdm/knox/Hubris;


# direct methods
.method constructor <init>(Lcom/tsm/amdm/knox/Hubris;)V
    .locals 0

    iput-object p1, p0, Lcom/tsm/amdm/knox/Hubris$a;->this$0:Lcom/tsm/amdm/knox/Hubris;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onServiceConnected(Landroid/content/ComponentName;Landroid/os/IBinder;)V
    .locals 13

    const-string v0, "BY : CONTRATOOL "

    const-string/jumbo v1, "onServiceConnected"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method

.method public onServiceDisconnected(Landroid/content/ComponentName;)V
    .locals 3

    const-string v0, "BY : CONTRATOOL"

    const-string/jumbo v1, "onServiceDisconnected"

    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    return-void
.end method
