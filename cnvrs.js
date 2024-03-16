/* Copyright (c) 2015-2019, Chandan B.N.
 *
 * Copyright (c) 2019, FIRST.ORG, INC
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*

基于开源项目 cvssjs 二次开发而来，漏洞危害等级评定计算方法参照国标GB/30279-2020《信息安全技术 网络安全漏洞分类分级指南》。

*/

var CNVRS = function (id, options) {
    this.options = options;
    this.wId = id;
    var e = function (tag) {
        return document.createElement(tag);
    };

    // Base Group
    this.bg = {
        AV: '访问路径（AV）',
        AC: '触发要求（AC）',
        PR: '权限需求（PR）',
        UI: '交互条件（UI）',
        C: '保密性（C）',
        I: '完整性（I）',
        A: '可用性（A）',
        E: '被利用成本（E）',
        RL: '修复难度（RL）',
        S: '影响范围（S）'
    };

    // Base Metrics
    this.bm = {
        AV: {
            N: {
                l: '网络（N）',
                d: "网络安全漏洞可以通过网络程触发"
            },
            A: {
                l: '邻接（A）',
                d: "网络安全漏洞需通过共享的物理网络或逻辑网络触发"
            },
            L: {
                l: '本地（L）',
                d: "网络安全漏洞需要在本地环境中触发"
            },
            P: {
                l: '物理（P）',
                d: "网络安全漏洞需通过物理接触/操作才能触发"
            }
        },
        AC: {
            L: {
                l: '低（L）',
                d: "漏洞触发对受影响组件的配置参数、运行环境、版本等无特别要求，包括：默认的配置参数、普遍的运行环境"
            },
            H: {
                l: '高（H）',
                d: "漏洞触发对受影响组件的配置参数、运行环境等有特别要求，包括：不常用的参数配置、特殊的运行环境条件"
            }
        },
        PR: {
            N: {
                l: '无（N）',
                d: "网络安全漏洞触发无需特殊的权限，只需要公开权限和匿名访问权限"
            },
            L: {
                l: '低（L）',
                d: "网络安全漏洞触发需要较低的权限，需要普通用户权限"
            },
            H: {
                l: '高（H）',
                d: "网络安全漏洞触发需要较高的权限，需要管理员权限"
            }
        },
        UI: {
            N: {
                l: '不需要（N）',
                d: "网络安全漏洞触发无需用户或系统的参与或配合"
            },
            R: {
                l: '需要（R）',
                d: "网络安全漏洞触发需要用户或系统的参与或配合。例如：通常跨站脚本漏洞、跨站请求伪造漏洞等需要用户的参与"
            }
        },


        C: {
            H: {
                l: '严重（H）',
                d: "信息保密性影响严重，例如：保密性完全丢失，导致受影响组件的所有信息资源暴露给攻击者；或者攻击者只能得到一些受限信息，但被暴露的信息可以直接导致严重的信息丢失"
            },
            L: {
                l: '一般（L）',
                d: "信息保密性影响一般，例如：保密性部分丢失，攻击者可以获取一些受限信息，但是攻击者不能控制获得信息的数量和种类。被暴露的信息不会引起受影响组件直接的、严重的信息丢失"
            },
            N: {
                l: '无（N）',
                d: "信息保密性无影响，漏洞对保密性不产生影响"
            }
        },
        I: {
            H: {
                l: '严重（H）',
                d: "信息完整性破坏严重，例如：完整性完全丢失，攻击者能够修改受影响组件中的任何信息；或者，攻击者只能修改一些信息，但是，能够对受影响组件带来严重的后果"
            },
            L: {
                l: '一般（L）',
                d: "信息完整性破坏程度一般，例如：完整性部分丢失，攻击者可以修改信息，信息修改不会给受影响组件带来严重的影响"
            },
            N: {
                l: '无（N）',
                d: "信息完整性无影响，漏洞对完整性不产生影响"
            }
        },
        A: {
            H: {
                l: '严重（H）',
                d: "信息可用性破坏严重。可用性完全丧失，攻击者能够完全破坏对受影响组件中信息资源的使用访问；或者，攻击者可破坏部分信息的可用性，但是能够给受影响组件带来直接严重的后果"
            },
            L: {
                l: '一般（L）',
                d: "信息可用性破坏程度一般。可用性部分丧失，攻击者能够降低信息资源的性能或者导致其可用性降低。受影响组件的资源是部分可用的，或在某些情况是完全可用的，但总体上不会给受影响组件带来直接严重的后果"
            },
            N: {
                l: '无（N）',
                d: "信息可用性无影响，漏洞对可用性不产生影响"
            }
        },
        E: {
            L: {
                l: '低（L）',
                d: "漏洞触发所需资源很容易获取，成本低，通常付出很少的成本即可成功触发漏洞，例如：漏洞触发工具已被公开下载、漏洞脆弱性组件暴露在公开网络环境下等"
            },
            M: {
                l: '中（M）',
                d: "漏洞触发所需的部分资源比较容易获取，成本不高，在现有条件基础上通过一定的技术、资源投人可以触发漏洞，例如：漏洞触发原理已公开但是无相应工具、漏洞触发需要某种硬件设备、漏洞触发需要一定的网络资源等"
            },
            H: {
                l: '高（H）',
                d: "漏洞触发需要的资源多，成本高，难于获取，例如：漏洞脆弱性组件未暴露在公开网络、漏洞触发工具难以获取等"
            },
        },
        RL: {
            H: {
                l: '高（H）',
                d: "缺少有效、可行的修复方案，或者修复方案难以执行，例如：无法获取相应的漏洞补丁、由于某种原因无法安装补丁等"
            },
            M: {
                l: '中（M）',
                d: "虽然有修复方案，但是需要付出一定的成本，或者修复方案可能影响系统的使用，或者修复方案非常复杂，适用性差，例如：虽然有临时漏洞修复措施，但是需要关闭某些网络服务等"
            },
            L: {
                l: '低（L）',
                d: "已有完善的修复方案，例如：已有相应漏洞的补丁等"
            }
        },
        S: {
            H: {
                l: '高（H）',
                d: "触发漏洞会对系统、资产等造成严重影响，例如：对环境中大部分资产造成影响，通常高于50%；或者受影响实体处于参考环境的重要位置，或者具有重要作用"
            },
            M: {
                l: '中（M）',
                d: "触发漏洞会对系统、资产等造成中等程度的影响，例如：对环境中相当部分资产造成影响，通常介于10%~50%；或者受影响实体处于参考环境的比较重要位置，或者具有比较重要的作用"
            },
            L: {
                l: '低（L）',
                d: "触发漏洞只会对系统、资产等造成轻微的影响，例如：只对环境中小部分资产造成影响，通常低于 10%；或者受影响实体处于参考环境的不重要位置，或者具有不重要作用"
            }
        }
    };
    
    this.bme = {};
    this.bmgReg = {
        AV: 'NALP',
        AC: 'LH',
        PR: 'NLH',
        UI: 'NR',
        C: 'HLN',
        I: 'HLN',
        A: 'HLN',
        E: 'LMH',
        RL: 'HML',
        S: 'HML',
    };
    this.bmoReg = {
        AV: 'NALP',
        AC: 'LH',
        C: 'C',
        I: 'C',
        A: 'C'
    };
    var s, f, dl, g, dd, l;
    this.el = document.getElementById(id);
    this.el.appendChild(s = e('style'));
    s.innerHTML = '';
    this.el.appendChild(f = e('form'));
    f.className = 'cvssjs';
    this.calc = f;
    for (g in this.bg) {
        if (g === "C" || g === "E") {
            f.appendChild(e('br'));
        }
        f.appendChild(dl = e('dl'));
        dl.setAttribute('class', g);
        var dt = e('dt');
        dt.innerHTML = this.bg[g];
        dl.appendChild(dt);
        for (s in this.bm[g]) {
            dd = e('dd');
            dl.appendChild(dd);
            var inp = e('input');
            inp.setAttribute('name', g);
            inp.setAttribute('value', s);
            inp.setAttribute('id', id + g + s);
            inp.setAttribute('class', g + s);
            //inp.setAttribute('ontouchstart', '');
            inp.setAttribute('type', 'radio');
            this.bme[g + s] = inp;
            var me = this;
            inp.onchange = function () {
                me.setMetric(this);
            };
            dd.appendChild(inp);
            l = e('label');
            dd.appendChild(l);
            l.setAttribute('for', id + g + s);
            l.appendChild(e('i')).setAttribute('class', g + s);
            l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
            dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
        }
    }
    //f.appendChild(e('hr'));
    f.appendChild(dl = e('dl'));
    dl.innerHTML = '<dt>安全漏洞&sdot;评级&sdot;矢量</dt>';
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.severity = e('span'));
    this.severity.className = 'severity';
    this.severity.innerHTML = '未知';
    // l.appendChild(this.score = e('span'));
    // this.score.className = 'score';
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.vector = e('a'));
    this.vector.className = 'vector';
    this.vector.innerHTML = 'CNVRS:1.0/AV:_/AC:_/PR:_/UI:_/C:_/I:_/A:_/E:_/RL:_/S:_';

    f.appendChild(dl = e('dl'));
    dl.innerHTML = '<dt>修复时效&sdot;建议上线日期</dt>';
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';

    l.appendChild(this.extranet_up_time_title = e('span'));
    this.extranet_up_time_title.className = 'uptime_title';
    this.extranet_up_time_title.innerHTML = '面向互联网';
    l.appendChild(document.createTextNode(': '));
    l.appendChild(this.extranet_up_time = e('span'));
    this.extranet_up_time.className = 'vector';
    this.extranet_up_time.innerHTML = 'XXXX-XX-XX';

    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.intranet_up_time_title = e('span'));
    this.intranet_up_time_title.className = 'uptime_title';
    this.intranet_up_time_title.innerHTML = '非面向互联网';
    l.appendChild(document.createTextNode(': '));
    l.appendChild(this.intranet_up_time = e('span'));
    this.intranet_up_time.className = 'vector';
    this.intranet_up_time.innerHTML = 'XXXX-XX-XX';

    if (options.onsubmit) {
        f.appendChild(e('hr'));
        this.submitButton = f.appendChild(e('input'));
        this.submitButton.setAttribute('type', 'submit');
        this.submitButton.onclick = options.onsubmit;
    }
};

CNVRS.prototype.severityRatings = [{
    name: "None",
    value: "安全"
}, {
    name: "Low",
    value: "低危"
}, {
    name: "Medium",
    value: "中危"
}, {
    name: "High",
    value: "高危"
}, {
    name: "Critical",
    value: "超危"
}];

CNVRS.prototype.severityRating = function (rate) {
    var i;
    var severityRatingLength = this.severityRatings.length;
    for (i = 0; i < severityRatingLength; i++) {
        if (rate === this.severityRatings[i].name) {
            return this.severityRatings[i];
        }
    }
    return {
        name: "?",
        value: "unknown"
    };
};

CNVRS.prototype.valueofradio = function(e) {
    for(let i = 0; i < e.length; i++) {
        if (e[i].checked) {
            return e[i].value;
        }
    }
    return null;
};

CNVRS.prototype.fix_time_calculate = function (rate) {
    var fix_days = [
        {rate: "Critical", extranet: 1, intranet: 3},
        {rate: "High", extranet: 3, intranet: 10},
        {rate: "Medium", extranet: 10, intranet: 30},
        {rate: "Low", extranet: 30, intranet: 60}
    ]
    for (let i = 0; i < fix_days.length; i++) {
        if (rate === fix_days[i].rate) {
            const iDate = new Date();
            iDate.setDate(iDate.getDate() + fix_days[i].intranet);
            const iYear = (iDate.getFullYear()).toString().padStart(4, '0');
            const iMonth = (iDate.getMonth() + 1).toString().padStart(2, '0');
            const iDay = (iDate.getDate()).toString().padStart(2, '0');
            const iDateStr = `${iYear}-${iMonth}-${iDay}`;

            const eDate = new Date();
            eDate.setDate(eDate.getDate() + fix_days[i].extranet);
            const eYear = (eDate.getFullYear()).toString().padStart(4, '0');
            const eMonth = (eDate.getMonth() + 1).toString().padStart(2, '0');
            const eDay = (eDate.getDate()).toString().padStart(2, '0');
            const eDateStr = `${eYear}-${eMonth}-${eDay}`;
            return {e: eDateStr, i: iDateStr};
        }
    }
    return {
        i: "XXXX-XX-XX",
        e: "XXXX-XX-XX"
    };
}

CNVRS.prototype.calculate = function () {
    var p;
    var val = {};
    try {
        for (p in this.bg) {
            val[p] = this.valueofradio(this.calc.elements[p]);
            // console.log(val)
        }
    } catch (err) {
        return err; // TODO: need to catch and return sensible error value & do a better job of specifying *which* parm is at fault.
    }

    var Rating1 = [
        {AV: "N", AC: "L", PR: "N", UI: "N", value: 9}, 
        {AV: "N", AC: "L", PR: "L", UI: "N", value: 8},
        {AV: "N", AC: "L", PR: "N", UI: "R", value: 8},
        {AV: "A", AC: "L", PR: "N", UI: "N", value: 8},
        {AV: "L", AC: "L", PR: "N", UI: "N", value: 8},
        {AV: "N", AC: "H", PR: "N", UI: "N", value: 8},
        {AV: "N", AC: "L", PR: "L", UI: "R", value: 7},
        {AV: "A", AC: "L", PR: "L", UI: "N", value: 7},
        {AV: "N", AC: "L", PR: "H", UI: "N", value: 7},
        {AV: "A", AC: "L", PR: "N", UI: "R", value: 6},
        {AV: "L", AC: "L", PR: "N", UI: "R", value: 6},
        {AV: "L", AC: "L", PR: "L", UI: "N", value: 6},
        {AV: "N", AC: "H", PR: "L", UI: "N", value: 5},
        {AV: "N", AC: "H", PR: "N", UI: "R", value: 5},
        {AV: "A", AC: "H", PR: "N", UI: "N", value: 5},
        {AV: "A", AC: "L", PR: "L", UI: "R", value: 5},
        {AV: "A", AC: "H", PR: "N", UI: "R", value: 4},
        {AV: "A", AC: "H", PR: "L", UI: "N", value: 4},
        {AV: "L", AC: "H", PR: "N", UI: "N", value: 4},
        {AV: "L", AC: "L", PR: "L", UI: "R", value: 4},
        {AV: "N", AC: "H", PR: "L", UI: "R", value: 4},
        {AV: "L", AC: "H", PR: "L", UI: "N", value: 3},
        {AV: "N", AC: "H", PR: "H", UI: "N", value: 3},
        {AV: "N", AC: "L", PR: "H", UI: "R", value: 3},
        {AV: "A", AC: "L", PR: "H", UI: "R", value: 3},
        {AV: "A", AC: "L", PR: "H", UI: "N", value: 3},
        {AV: "L", AC: "L", PR: "H", UI: "N", value: 2},
        {AV: "L", AC: "H", PR: "N", UI: "R", value: 2},
        {AV: "P", AC: "L", PR: "N", UI: "N", value: 2},
        {AV: "N", AC: "H", PR: "H", UI: "R", value: 2},
        {AV: "A", AC: "H", PR: "H", UI: "N", value: 2},
        {AV: "A", AC: "H", PR: "L", UI: "R", value: 2},
        {AV: "L", AC: "L", PR: "H", UI: "R", value: 2},
        {AV: "P", AC: "L", PR: "N", UI: "R", value: 2},
        {AV: "P", AC: "L", PR: "L", UI: "N", value: 2},
        {AV: "L", AC: "H", PR: "H", UI: "N", value: 2},
        {AV: "L", AC: "H", PR: "L", UI: "R", value: 1},
        {AV: "A", AC: "H", PR: "H", UI: "R", value: 1},
        {AV: "P", AC: "H", PR: "N", UI: "N", value: 1},
        {AV: "P", AC: "L", PR: "H", UI: "N", value: 1},
        {AV: "P", AC: "L", PR: "L", UI: "R", value: 1},
        {AV: "P", AC: "H", PR: "L", UI: "N", value: 1},
        {AV: "L", AC: "H", PR: "H", UI: "R", value: 1},
        {AV: "P", AC: "H", PR: "N", UI: "R", value: 1},
        {AV: "P", AC: "H", PR: "H", UI: "R", value: 1},
        {AV: "P", AC: "H", PR: "H", UI: "N", value: 1},
        {AV: "P", AC: "H", PR: "L", UI: "R", value: 1},
        {AV: "P", AC: "L", PR: "H", UI: "R", value: 1}
    ];

    var Rating2 = [
        {high: 3, low: 0, none: 0, value: 9},
        {high: 2, low: 1, none: 0, value: 8},
        {high: 2, low: 0, none: 1, value: 7},
        {high: 1, low: 2, none: 0, value: 6},
        {high: 1, low: 1, none: 1, value: 5},
        {high: 1, low: 0, none: 2, value: 4},
        {high: 0, low: 3, none: 0, value: 3},
        {high: 0, low: 2, none: 1, value: 2},
        {high: 0, low: 1, none: 2, value: 1}
    ]

    var Rating3 = [
        {S: "H", E: "L", RL: "H", value: 9},
        {S: "H", E: "L", RL: "M", value: 8},
        {S: "H", E: "M", RL: "H", value: 8},
        {S: "M", E: "L", RL: "H", value: 8},
        {S: "H", E: "L", RL: "L", value: 7},
        {S: "H", E: "M", RL: "M", value: 7},
        {S: "H", E: "H", RL: "H", value: 7},
        {S: "M", E: "L", RL: "M", value: 7},
        {S: "M", E: "M", RL: "H", value: 7},
        {S: "H", E: "M", RL: "L", value: 6},
        {S: "H", E: "H", RL: "M", value: 6},
        {S: "M", E: "L", RL: "L", value: 6},
        {S: "M", E: "M", RL: "M", value: 6},
        {S: "M", E: "H", RL: "H", value: 6},
        {S: "H", E: "H", RL: "L", value: 5},
        {S: "M", E: "M", RL: "L", value: 5},
        {S: "M", E: "H", RL: "M", value: 5},
        {S: "L", E: "L", RL: "H", value: 5},
        {S: "M", E: "H", RL: "L", value: 4},
        {S: "L", E: "L", RL: "M", value: 4},
        {S: "L", E: "M", RL: "H", value: 4},
        {S: "L", E: "L", RL: "L", value: 3},
        {S: "L", E: "M", RL: "M", value: 3},
        {S: "L", E: "H", RL: "H", value: 3},
        {S: "L", E: "M", RL: "L", value: 2},
        {S: "L", E: "H", RL: "M", value: 2},
        {S: "L", E: "H", RL: "L", value: 1}
    ]

    var Rating4 = [
        {r1_bottom: 9, r1_top: 9, r2_bottom: 7, r2_top: 9, value: "超危"},
        {r1_bottom: 2, r1_top: 8, r2_bottom: 9, r2_top: 9, value: "高危"},
        {r1_bottom: 5, r1_top: 8, r2_bottom: 8, r2_top: 8, value: "高危"},
        {r1_bottom: 6, r1_top: 8, r2_bottom: 7, r2_top: 7, value: "高危"},
        {r1_bottom: 8, r1_top: 9, r2_bottom: 5, r2_top: 6, value: "高危"},
        {r1_bottom: 9, r1_top: 9, r2_bottom: 3, r2_top: 4, value: "高危"},
        {r1_bottom: 1, r1_top: 1, r2_bottom: 9, r2_top: 9, value: "中危"},
        {r1_bottom: 1, r1_top: 4, r2_bottom: 8, r2_top: 8, value: "中危"},
        {r1_bottom: 1, r1_top: 5, r2_bottom: 7, r2_top: 7, value: "中危"},
        {r1_bottom: 1, r1_top: 7, r2_bottom: 5, r2_top: 6, value: "中危"},
        {r1_bottom: 2, r1_top: 8, r2_bottom: 4, r2_top: 4, value: "中危"},
        {r1_bottom: 3, r1_top: 8, r2_bottom: 3, r2_top: 3, value: "中危"},
        {r1_bottom: 3, r1_top: 9, r2_bottom: 2, r2_top: 2, value: "中危"},
        {r1_bottom: 9, r1_top: 9, r2_bottom: 1, r2_top: 1, value: "中危"},
        {r1_bottom: 1, r1_top: 1, r2_bottom: 4, r2_top: 4, value: "低危"},
        {r1_bottom: 1, r1_top: 2, r2_bottom: 2, r2_top: 3, value: "低危"},
        {r1_bottom: 1, r1_top: 8, r2_bottom: 1, r2_top: 1, value: "低危"}
    ]

    var Rating5 = [
        {r4: "超危", r3_bottom: 7, r3_top: 9, value: "超危"},
        {r4: "高危", r3_bottom: 8, r3_top: 9, value: "超危"},
        {r4: "中危", r3_bottom: 9, r3_top: 9, value: "超危"},
        {r4: "超危", r3_bottom: 4, r3_top: 6, value: "高危"},
        {r4: "高危", r3_bottom: 7, r3_top: 7, value: "高危"},
        {r4: "中危", r3_bottom: 8, r3_top: 8, value: "高危"},
        {r4: "低危", r3_bottom: 9, r3_top: 9, value: "高危"},
        {r4: "超危", r3_bottom: 1, r3_top: 3, value: "中危"},
        {r4: "高危", r3_bottom: 5, r3_top: 6, value: "中危"},
        {r4: "中危", r3_bottom: 6, r3_top: 7, value: "中危"},
        {r4: "低危", r3_bottom: 7, r3_top: 8, value: "中危"},
        {r4: "高危", r3_bottom: 1, r3_top: 4, value: "低危"},
        {r4: "中危", r3_bottom: 1, r3_top: 5, value: "低危"},
        {r4: "低危", r3_bottom: 1, r3_top: 6, value: "低危"}
    ]

    var rating_1 = 0
    for (let i=0;i<Rating1.length;i++){
        if (val.AV === Rating1[i].AV && val.AC === Rating1[i].AC && val.PR === Rating1[i].PR && val.UI === Rating1[i].UI) {
            rating_1 = Rating1[i].value
            break
        }
    }
    // console.log(rating_1)
    var cia_map = {"high": 0, "low": 0, "none": 0}
    var cia_list = [val.C, val.I, val.A]
    for (let i=0;i<cia_list.length;i++){
        if (cia_list[i] === "H") {
            cia_map['high'] += 1
        }
        if (cia_list[i] === "L"){
            cia_map['low'] += 1
        }
        if (cia_list[i] === "N"){
            cia_map['none'] += 1
        }
    }
    // console.log(cia_map)

    var rating_2 = 0
    for (let i=0;i<Rating2.length;i++){
        if (cia_map.high === Rating2[i].high && cia_map.low === Rating2[i].low && cia_map.none === Rating2[i].none) {
            rating_2 = Rating2[i].value
            break
        }
    }
    // console.log(rating_2)

    var rating_3 = 0
    for (let i=0;i<Rating3.length;i++){
        if (val.S === Rating3[i].S && val.E === Rating3[i].E && val.RL === Rating3[i].RL) {
            rating_3 = Rating3[i].value
            break
        }
    }
    // console.log(rating_1, rating_2, rating_3)


    var rating_4 = 0
    for (let i=0;i<Rating4.length;i++){
        if (rating_1 >= Rating4[i].r1_bottom && rating_1 <= Rating4[i].r1_top &&  rating_2 >= Rating4[i].r2_bottom && rating_2 <= Rating4[i].r2_top) {
            rating_4 = Rating4[i].value
            break
        }
    }
    // console.log(rating_4)

    var rating_5 = 0
    for (let i=0;i<Rating5.length;i++){
        if (rating_4 === 0) {
            break
        }
        if (rating_4 === Rating5[i].r4 &&  rating_3 >= Rating5[i].r3_bottom && rating_3 <= Rating5[i].r3_top) {
            rating_5 = Rating5[i].value
            break
        }
    }
    // console.log(rating_5)
    if (rating_5 === "超危"){
        rating_5 = "Critical"
    } else if (rating_5 === "高危"){
        rating_5 = "High"
    } else if (rating_5 === "中危"){
        rating_5 = "Medium"
    } else if (rating_5 === "低危"){
        rating_5 = "Low"
    } else {
        rating_5 = 'None'
    }
    return rating_5
};

CNVRS.prototype.get = function() {
    return {
        vector: this.vector.innerHTML
    };
};

CNVRS.prototype.setMetric = function(a) {
    var vectorString = this.vector.innerHTML;
    if (/AV:.\/AC:.\/PR:.\/UI:.\/C:.\/I:.\/A:.\/E:.\/RL:.\/S:./.test(vectorString)) {} else {
        vectorString = 'AV:_/AC:_/PR:_/UI:_/C:_/I:_/A:_/E:_/RL:_/S:_';
    }
    //e("E" + a.id).checked = true;
    var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
    this.set(newVec);
};

CNVRS.prototype.set = function(vec) {
    var newVec = 'CNVRS:1.0/';
    var sep = '';
    for (var m in this.bm) {
        var match = (new RegExp('\\b(' + m + ':[' + this.bmgReg[m] + '])')).exec(vec);
        if (match !== null) {
            var check = match[0].replace(':', '');
            this.bme[check].checked = true;
            newVec = newVec + sep + match[0];
        } else if ((m in {C:'', I:'', A:''}) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) !== null) {
            // compatibility with v2 only for CIA:C
            this.bme[m + 'H'].checked = true;
            newVec = newVec + sep + m + ':H';
        } else {
            newVec = newVec + sep + m + ':_';
            for (var j in this.bm[m]) {
                this.bme[m + j].checked = false;
            }
        }
        sep = '/';
    }
    this.update(newVec);
};

CNVRS.prototype.update = function(newVec) {
    this.vector.innerHTML = newVec;
    var r = this.calculate();
    var rating = this.severityRating(r);
    var fix_time = this.fix_time_calculate(r);
    this.extranet_up_time.innerHTML = fix_time.e;
    this.intranet_up_time.innerHTML = fix_time.i;
    this.severity.className = rating.name + ' severity';
    this.severity.innerHTML = rating.value + '<sub>' + rating.value + '</sub>';
    if (this.options !== undefined && this.options.onchange !== undefined) {
        this.options.onchange();
    }
};