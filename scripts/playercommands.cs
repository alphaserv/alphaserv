
//A player command that allows admin players to execute cubescript code on the server in-game.
//Syntax is "#eval [<code>]", with the square brackets included and <code> being your code.
playercmd_eval = [
    if (strcmp (player_priv $cn) "admin") [do [@arg1]] [privmsg $cn (err "Permission Denied")]
]

playercmd_script = [
    local filename (format "scripts/%1" $arg1)
    playercmd_eval [exec "@filename"]
]

playercmd_specall = [
    if (strcmp (player_priv $cn) "admin") [
        foreach (players) [spec $arg1]
    ] [privmsg $cn (err "Permission Denied")]
]

playercmd_unspecall = [
    if (strcmp (player_priv $cn) "admin") [
        foreach (players) [unspec $arg1]
    ] [privmsg $cn (err "Permission Denied")]
]

playercmd_names = [
    parameters target
    if (strcmp (player_priv $cn) "none") [throw runtime.playercmd.names.permission_denied]
    privmsg $cn (showaliases $target)
]

playercmd_who = [
    if (strcmp (player_priv $cn) "none") [throw runtime.playercmd.names.permission_denied]
    privmsg $cn (who)
]

playercmd_invadmin = [
    parameters pass
    if (adminpass $pass) [setpriv $cn admin] [privmsg $cn (err "Command Failed")]
]

playercmd_group = [
    if (>= (listlen $arguments) 2) [
	reference tag arg1
        reference t_team arg2
        foreach (players) [
                if ((match $tag (player_name $arg1))) [ msg (err (format "Moving %2 to %1 for team grouping" $t_team (player_name $arg1)) ) ; setteam $arg1 $t_team ]
        ]
    ] [privmsg $cn (err "Missing argument. Allows team grouping of players by tag. Syntax #group <tag> <team>.")]
]

playercmd_setmotd = [
    if (>= (listlen $arguments) 1) [
	motd = $arg1
	privmsg $cn (format "MOTD Changed to %1" (magenta $motd) )
    ]
]

playercmd_slap = [
    parameters target
    if (strcmp (player_priv $cn) "admin") [
        msg (grey [*@(concol 7 (player_name $target)) got slapped by @(orange (player_name $cn))*])
    ] [privmsg $cn (err "Permission Denied")]
]
