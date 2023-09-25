<?php
/* Copyright (C) 2022 Mathieu Moulin iProspective <contact@iprospective.fr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

dol_include_once('custom/mmicommon/class/mmi_actions.class.php');

/**
 * Class ActionsMMISecurity
 */
class ActionsMMISecurity extends MMI_Actions_1_0
{
	const MOD_NAME = 'mmisecurity';

    /**
     * Restriction à la connexion
     */
    function updateSession($parameters, &$object, &$action, $hookmanager)
    {
        $error = 0; // Error counter
        $print = '';
    
        if ($this->in_context($parameters, 'main')) {
            if (!$this->login_check($object))
                die('Unauthorized');
        }
    
        if (empty($this->errors))
        {
            $this->resprints = $print;
            return 0; // or return 1 to replace standard code
        }
        else
        {
            return -1;
        }
    }

    /**
     * Restriction à la connexion
     */
    function afterLogin($parameters, &$object, &$action, $hookmanager)
    {
        global $conf;

        $error = 0; // Error counter
        $print = '';
    
        if ($this->in_context($parameters, 'login')) {
            if (!$this->login_check($object))
                die('Unauthorized');
        }
    
        if (empty($this->errors))
        {
            $this->resprints = $print;
            return 0; // or return 1 to replace standard code
        }
        else
        {
            return -1;
        }
    }

    protected function login_check($user)
    {
        global $conf;

        // If user NOT admin and has ip restrictions
        if (!$user->admin && !empty($user->array_options['options_ip_connect_limit'])) {
            if (!empty($_SERVER['REMOTE_ADDR']) && !empty($conf->global->MMISECURITY_IP_LIMITATION)) {
                $ips = preg_split('/[,; ]/', $conf->global->MMISECURITY_IP_LIMITATION);
                //var_dump($ips, $_SERVER['REMOTE_ADDR']);
                if (!in_array($_SERVER['REMOTE_ADDR'], $ips))
                    return false;
            }
        }

        return true;
    }
}

ActionsMMISecurity::__init();
